import ox.scl._
import scala.collection.BitSet
import scala.util.matching.Regex
import scala.io.Source
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference
import scala.collection.concurrent.TrieMap

object TripwiresChecker {

  var multiThreadTime = 0.0;
  var file = "";

  type TriggerParams = (Option[Regex], Option[Regex], Option[Regex], Option[Regex], Option[Regex], Option[Double], Option[Double]);
  type RawData = (String, String, String, String, String, Double)

  // Format of the CSV to read
  case class CsvRow(protocol: String, multiplex: String, length: String, nt:String, misc: String, time: Double)

  // Used to store each individual state in an attack pattern
  class State(val id: String, 
              val pattern: String, 
              val isOutput: Boolean, 
              val children: List[String], 
              val parents: List[String], 
              timeout1: Map[String, Double], 
              val triggerParams : TriggerParams) { 
    def timeout(key : String) : Double = {
      if (timeout1.contains(key)) timeout1(key) else 0}
  }

  // 
  class StateModelRecord(val id: String, val commitTime: Double)


  class Model(state1: Map[String, StateModelRecord], transition1: Map[String, Double]) {
    private var states = state1;
    private var transitions = transition1;
    def state : Map[String, StateModelRecord] = states;
    def transition : Map[String, Double] = transitions;
    def addTransition(k : String, v : Double) = {transitions += (k -> v)}
    def removeState(id: String) = {states = states.removed(id)}
    def updateState(id: String, newTime: Double) = {
      val update = new StateModelRecord(id, newTime);
      states = states.updated(id, update);
    }
  }

  // Each attack pattern
  class Pattern(val id: String, val description: String, val states: Map[String, State]) {
    def s(k: String) : State = states(k);
  }

  class Transition(orig: String, target: String) {
    def original : String = orig;
    def to : String = target;
  }

  object Run {
    var m = eternal._1;
    val conc = new CentralModel(m)
    var data : Vector[RawData] = Vector()
    
    private val transitionsCount = new TrieMap[String, TrieMap[Int, Unit]]
    var allTransitions : List[(Int, String)] = List()

    // CentralModel is used for all the concurrent datatype accesses
    class CentralModel(start: Model){
      // Index indicates which entry from the log file to check next
      private var index = new AtomicInteger(-1)
      
      // current is an atomic reference to the current State, Transition and 
      // set of transitions that are to be checked
      private var current = new AtomicReference((start.state, start.transition, BitSet()))
      
      // Used to sto
      val alerted = new TrieMap[String, Unit]      

      // This is used when a thread is looking to check the next entry, with 
      // this returning the next index to be checked, the current 'collective' 
      // state and transition and the BitSet corresponding to the transitions
      def incAndGetIM : (Int, Map[String, StateModelRecord], Map[String, Double], BitSet) = { 
        val (s, t, b) = current.get
        return (index.incrementAndGet, s, t, b) 
      }

      // Used to 'rewind' index back whenever a previous transition has been 
      // discovered, allowing us to maintain correctness of the search
      /* NB. we now also use the bitSet to ensure that no transitions are 
         permanently overwritten and deleted by rewind; this is because the 
         previous safety invariant was insufficient and was discovered when 
         reporting the first and last transition times of each state */
      def rewind(newS: Map[String, StateModelRecord], newT: Map[String, Double], newVal: Int, trans: List[String], bitSet : BitSet) = {
        var done = false
        while (!done) {
          val c = current.get
          if (newVal <= index.get && c._3.range(0, newVal).equals(bitSet)) {
            //need to rewind
            done = current.compareAndSet(c, (newS, newT, bitSet.union(BitSet(newVal))))
            if (done) {
              index.set(newVal)
              for (t <- trans) {
                val a = transitionsCount.getOrElseUpdate(t, new TrieMap[Int, Unit])
                a.putIfAbsent(newVal, ())
              }
            }
          }
          else done = true // History not invalidated
        }
      }
    }

    // The Attack Model and Pattern for the Eternal Blue exploit
    def eternal : (Model, Pattern) = {
      // Defines the states for the Eternal Blue exploit attack pattern
      val s0 = new State("s0", "all", false, List("s1"), Nil, Map("s1" -> 3600),
                         (None, None, None, None, None, None, None));
      val s1 = new State("s1", "eternal", false, List("s2", "s3"), List("s0"), 
                         Map("s2"->3600, "s3"->3600), 
                         (Some("SMB".r), None, Some("[1-9][0-9]{3,}".r), None, Some("NT Trans Request".r), None, None))
      val s2 = new State("s2", "eternal", false, List("s3"), List("s1"), 
                         Map("s3"->3600), 
                         (Some("SMB".r), None, None, None, Some("Trans2 Secondary Request".r), None, None))
      val s3 = new State("s3", "eternal", false, List("s4"), List("s1", "s2"), 
                         Map("s4"->3600), 
                         (Some("SMB".r), None, None, Some("STATUS_INVALID_PARAMETER".r), Some("Trans2 Response".r), None, None))
      val s4 = new State("s4", "eternal", true, Nil, List("s3"), Map(), 
                         (Some("SMB".r), Some("82".r), None, Some("STATUS_NOT_IMPLEMENTED".r), Some("Trans2 Response".r), None, None))
      
      // Define the Eternal Blue attack pattern
      val eternal = new Pattern("eternal", "Eternal blue exploit (CVE-2017-0144)", Map("s0"->s0,"s1"->s1,"s2"->s2,"s3"->s3,"s4"->s4))

      // The initial model, with the initial state and no transitions
      val mod = new Model(Map("s0" -> new StateModelRecord("s0", 0.0)), Map.empty[String, Double])

      return (mod, eternal)
    }


    // This defines the attack pattern and then runs the workers
    // This should probably be refactored so that the attack 
    // pattern(s) can be chosen from the command line
    def concRunner(noWorkers: Int, noOutput: Boolean, noCount: Boolean) = {
      val (model, pattern) = eternal

      println("Checking for occurances of " + pattern.description)
      
      // The array of worker threads
      val threadArray: Array[MyWorker] = new Array[MyWorker](noWorkers)
      for (i <- 0 until noWorkers) {
        threadArray(i) = new MyWorker(i, model, pattern, noOutput, noWorkers)
        threadArray(i).setName(i.toString)
        threadArray(i).setPriority(10)
      }
      
      // Run threads and wait for them all to terminate, times are for 
      // performance monitoring
      val startTime = System.nanoTime()
      for (t <- threadArray) t.start()
      for (t <- threadArray) t.join()
      val endTime = System.nanoTime()
      multiThreadTime = (endTime - startTime) / 1000000.0      
      
      val (_, finalS, finalT, _) = conc.incAndGetIM
      if (! noOutput) {
        for (k <- transitionsCount.keys.toList.sorted) {println(k + " {Occurance(s): " + transitionsCount.getOrElse(k, null.asInstanceOf[TrieMap[Int, Unit]]).size + ", First occurance: " + finalT.getOrElse(k, "N/A")+"}")}
        for (k <- finalS.keys.toList.sorted) {
          if (k != "s0") println(k + " {Last transition to: " + finalS(k).commitTime + "}")
          else println("s0 {Original state}")
        }
      }
    }


    // A function to read the csv input file and return a vector of RawData objects
    // Any relevant data from the csv file can be extracted by changing 
    // the column headers
    def readData(file: String, furthest: Int) : Vector[RawData] = {
      val csvFile = Source.fromFile(file)
      val lines = csvFile.getLines().toList
      csvFile.close()

      // Extract header and data rows
      val header = lines.head.replaceAll("\"", "").split(",").map(_.trim)
      val data = lines.tail

      // Define index of relevant columns
      val timeIndex = header.indexOf("Time")
      val protocolIndex = header.indexOf("Protocol")
      val infoIndex = header.indexOf("Info")
      val lengthIndex = header.indexOf("Length")
      val multiplexIndex = header.indexOf("Multiplex ID")      
      val ntIndex = header.indexOf("NT Status")

      // Process the rows of data
      val processedData = data.map { row =>
        val values = row.replaceAll("\"", "").split((",")).map(_.trim)
        CsvRow(
          values(protocolIndex),
          values(multiplexIndex),
          values(lengthIndex),
          values(ntIndex),
          values.zipWithIndex.collect {
            case (value, index) if index != timeIndex =>
              value
          }.toList.toString,
          values(timeIndex).toDouble
        )
      }
      var revData = processedData.reverse
      // Create the output vector
      var outData = List.empty[RawData]
      while (revData != Nil) {
        val e = revData.head
        revData = revData.tail
        outData = (e.protocol, e.multiplex, e.length, e.nt, e.misc, e.time) +: outData
      }
      return(outData.toVector)
    }


    // Used to check if any of the Trigger params have occured in the 
    // current RawData entry
    // Should probably be changed to support a variable number of params
    def trigger(triggerParams: TriggerParams, userData : RawData) : Boolean = {
      val (aR, bR, cR, dR, eR, fTime, cTime) = triggerParams
      val (a, b, c, d, e, time) = userData
      if (aR.isDefined && ! aR.get.findFirstIn(a).isDefined) return false;
      else if (bR.isDefined && ! bR.get.findFirstIn(b).isDefined) return false;
      else if (cR.isDefined && ! cR.get.findFirstIn(c).isDefined) return false;
      else if (dR.isDefined && ! dR.get.findFirstIn(d).isDefined) return false;
      else if (eR.isDefined && ! eR.get.findFirstIn(e).isDefined) return false;
      else if (fTime.isDefined && cTime.isDefined && 
              (time.toDouble < fTime.get || time.toDouble > cTime.get)) return false;
      return true;
    }


    // Used to return the list of transitions and states that have been passed 
    // through to reach the marked output node
    // Can probably be improved, but seems to work and is only called when an
    // output alert is being produced
    def getTrace(stateId1: String, sModel: Map[String, StateModelRecord], tModel: Map[String, Double], attack: Pattern): List[String] = {
      var stateId = stateId1;
      if (stateId == "s0") {
        return Nil;
      }
      var result = List(stateId);
      var transitions = List.empty[String];
      for (parent <- attack.s(stateId).parents) {
        transitions = (parent + " " + stateId) :: transitions;
      }
      var ceilingTime : Double = 0.0;
      for (t <- transitions) {
        if (tModel(t) > ceilingTime) ceilingTime = tModel(t);
      }

      while (true) {
        var validTransitions = List.empty[(String, String)];
        if (attack.s(stateId).parents == Nil) return result;
        else {
          for (parent <- attack.s(stateId).parents) {
            validTransitions = (parent + ' ' + stateId, parent) :: validTransitions;
          }
        }

        if (validTransitions.isEmpty) return result;
        else {
          var targetTransition = validTransitions.head._1;
          var targetOriginal = validTransitions.head._2;
          for ((t, a) <- validTransitions) {
            if (tModel(t) > tModel(targetTransition) &&
              tModel(t) < ceilingTime) {
              targetTransition = t;
              targetOriginal = a;
            }
          }
          if (tModel(targetTransition) > ceilingTime) return result;
          else {
            result = targetOriginal :: result;
            stateId = targetOriginal;
            ceilingTime = transitions.map(t => tModel(t)).max;
          }
        }
      }
      return result;
    }

    // This is used to output any alerts as they occur; each alert will only 
    // show once even if the final transition occurs multiple times
    // NB. This is currently not guaranteed to report the first occurance of an 
    // isOutput transition from in the csv; it currently reports when the first 
    // thread finishes processing a transition to the relevant isOutput state
    class TraceWorker(stateModel: Map[String, StateModelRecord], transitionModel: Map[String, Double], attack: Pattern, to: String, now: Double) extends Thread{
      override def run() = {
        if (conc.alerted.putIfAbsent(to, ()) == None) {
          // Alert has not yet been generated for this output state
          var current = getTrace(to, stateModel, transitionModel, attack)
          print("Multithreaded alert for state \'" + to + "\' at log time "+ now + "s, trace: ")
          while(current.tail != Nil) {
            print(current.head + " -> ")
            current = current.tail
          }
          println(current.head)
        }
      }
    }


    // The worker definition
    class MyWorker(wId: Int, model: Model, attack: Pattern, noOutput: Boolean, noWorkers: Int) extends Thread {
      override def run() = {
        val length = data.length
        var i = 0
        var stateModel = model.state;
        var transitionModel = model.transition;
        var targetTransitions : List[Transition] = List();
        var newTransitions : List[String] = List();
        var now = 0.0;
        var updated = false
        var bitSet = BitSet()
        // Terminates if i < length
        // This could do with fixing as it allows some workers to potentially 
        // terminate before a rewind results in the being more data to process
        // Could be replaced using some consensus object where each thread can 
        // wait for all threads to declare that they're done before terminating 
        // and where any rewind releases the waiting threads
        while({val (i1, s1, t1, b1) = conc.incAndGetIM; i = i1; stateModel = s1; transitionModel = t1; bitSet = b1; i < length}) {
          updated = false
          newTransitions = Nil
          for ((t, s) <- stateModel) {
            for (c <- attack.s(s.id).children) {
              // Checks if any of the state's trigger params have been hit
              if (trigger(attack.s(c).triggerParams, data(i))) {
                now = data(i)._6
                updated = true;
                val t = new Transition(s.id, c)
                // Check that transition has occured prior to the timeout
                if (now <= s.commitTime + attack.s(s.id).timeout(c)) {
                  // Keep first transition time
                  transitionModel = transitionModel + 
                                    ((t.original + ' ' + t.to) -> 
                                      transitionModel.getOrElse((t.original + ' ' + t.to), now))
                  // Update times
                  val update = new StateModelRecord(t.to, now);
                  stateModel = stateModel.updated(t.to, update);
                  newTransitions = (t.original + ' ' + t.to) :: newTransitions
                  // Start new trace worker to check and output if new alert 
                  // generated
                  if (attack.s(t.to).isOutput && ! noOutput) {
                    val trace = new TraceWorker(stateModel, transitionModel, attack, t.to, now)
                    trace.run()
                  }
                }
                else stateModel = stateModel - t.original;
              }
            }
          }
          if (updated)  { 
            // Check if we need to 'rewind' the workers back to 
            // consider the new transition
            conc.rewind(stateModel, transitionModel, i, newTransitions, bitSet); 
          }
        }
      }
    }

    def main(args : Array[String]) = {
      val file = args(1)
      // Parse the input logs
      data = readData(file, 500000)
      val i = args(0).toInt
      // Run the system with i threads
      concRunner(i, false, false)
    }
  } 

  def main(args : Array[String]) = {
    if (args.size != 2) {
      println("Usage: TripwiresChecker N FILE\nWhere N is the number of workers " 
              + "to use and FILE is the .csv to be checked")
      System.exit(1)
    }
    file = args(1)
    val nArgs = Array(args(0), file)

    Run.main(nArgs);

    //println("Single threaded time taken (ms): " + singleThreadTime")
    println("Multi threaded time taken (ms): " + multiThreadTime)
  }
}

