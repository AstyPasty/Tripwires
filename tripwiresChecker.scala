import ox.scl._
import scala.collection.BitSet
import scala.util.matching.Regex
import scala.io.Source
import java.util.concurrent.atomic.AtomicInteger;
import scala.concurrent.duration._
import java.util.concurrent.ConcurrentHashMap
import scala.util.Random

object TripwiresChecker {

  var singleThreadTime = 0.0;
  var multiThreadTime = 0.0;
  var file = "";

  type TriggerParams = (Option[Regex], Option[Regex], Option[Regex], Option[Regex], Option[Regex], Option[Double], Option[Double]);
  type RawData = (String, String, String, String, String, Double)

  case class CsvRow(protocol: String, multiplex: String, length: String, nt:String, misc: String, time: Double)


  class State(id1: String, pattern1: String, isOutput1: Boolean, children1: List[String], parents1: List[String], timeout1: Map[String, Double], triggerParams1 : TriggerParams) { //RawData => Boolean) {//: TriggerParams) {
    def id : String = id1;
    def pattern : String = pattern1;//: Pattern = pattern1;
    def isOutput : Boolean = isOutput1;
    def children : List[String] = children1;
    def parents : List[String] = parents1;
    def timeout(key : String) : Double = {
      if (timeout1.contains(key)) timeout1(key) else 0}
    def triggerParams : TriggerParams = triggerParams1;
  }

  class StateModelRecord(id1: String, time1: Double) {
    def id : String = id1;
    def commitTime : Double =  time1;
  }


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

  class ConcModel(index1: Int, state1: Map[String, StateModelRecord], transition1: Map[String, Double]) {
    def index : Int = index1;
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

  class Pattern(id1: String, desc1: String, states1: Map[String, State]) {
    def id : String = id1;
    def desc : String = desc1;
    def states : Map[String, State] = states1;
    def s(k: String) : State = states1(k);
  }

  class Transition(orig: String, target: String) {
    def original : String = orig;
    def to : String = target;
  }

  object Run2 {
    val smr = new StateModelRecord("s0", 0.0)
    var m = new ConcModel(-1, Map("s0" -> smr), Map("s0" -> 0.0));
    val conc = new CentralModel(m)
    var data : Vector[RawData] = Vector()
    var transitionsCount = Map("s0 s1" -> 0, "s1 s2" -> 0, "s1 s3" -> 0, "s2 s3" -> 0, "s3 s4" -> 0)
    var allTransitions : List[(Int, String)] = List()


    class CentralModel(start: ConcModel){
      private var m : ConcModel = start
      private var m2 : Model = new Model(Map("s0" -> smr), Map("s0" -> 0.0));
      private val default = smr
      private var s2 : Map[String, StateModelRecord] = Map("s0" -> smr)
      private var t2 : Map[String, Double] = Map("s0" -> 0.0)
      private var t2vals = t2.values.toList.sorted
      private var t2valsLen = 1
      private var time2 : Double = -0.1
      private var a = -1
      private var aI = new AtomicInteger(-1)
      private val intLock = new Lock()
      private val modelLock = new Lock()
      private var traces = BitSet()
      private val traceLock = new Lock()
      private var checkTrans = true
      private var transBitSet = BitSet()
      def traceCheck(key: Int) : Boolean = {
        traceLock.acquire;
        if (traces.contains(key)) {traceLock.release; return false}
        traces = traces | BitSet(key)
        traceLock.release
        return true
      }
      def getI : Int = { return aI.incrementAndGet }
      def getM : ConcModel= { modelLock.acquire; val result = m; modelLock.release; return result }
      def getST : (Map[String, StateModelRecord], Map[String, Double])= { modelLock.acquire; val result = (s2, t2); modelLock.release; return result }
      def incAndGetIM : (Int, ConcModel) = { modelLock.acquire; val out = (aI.incrementAndGet, m); modelLock.release; return out }
      def rewind(newM: ConcModel, newVal: Int) = {
        modelLock.acquire; 
        if (newVal <= aI.get) {m = newM; aI.getAndSet(newVal)}
        modelLock.release
      }
      def incAndGetIM2 : (Int, Map[String, StateModelRecord], Map[String, Double], BitSet) = { modelLock.acquire; val out = (aI.incrementAndGet, s2, t2, transBitSet); modelLock.release; return out }
      def rewind2(newS: Map[String, StateModelRecord], newT: Map[String, Double], newVal: Int, trans: List[String], bitSet : BitSet) = {
        modelLock.acquire; 
        if (newVal <= aI.get && transBitSet.range(0, newVal).equals(bitSet)) {
          s2 = newS; 
          t2 = newT;
          transBitSet = bitSet.union(BitSet(newVal))
          for (t <- trans) allTransitions = (newVal, t) :: allTransitions
          aI.getAndSet(newVal);
        }
        modelLock.release
      }
    }

    def concEternal2(noWorkers: Int, noOutput: Boolean, noCount: Boolean) = {
      // Defines the states for the Eternal Blue exploit attack pattern
      val s0 = new State("s0", "all", false, List("s1"), Nil, Map("s1" -> 3600), (None, None, None, None, None, None, None));
      val s1 = new State("s1", "eternal", false, List("s2", "s3"), List("s0"), Map("s2"->3600, "s3"->3600), (Some("SMB".r), None, Some("[1-9][0-9]{3,}".r), None, Some("NT Trans Request".r), None, None))
      val s2 = new State("s2", "eternal", false, List("s3"), List("s1"), Map("s3"->3600), (Some("SMB".r), None, None, None, Some("Trans2 Secondary Request".r), None, None))
      val s3 = new State("s3", "eternal", false, List("s4"), List("s1", "s2"), Map("s4"->3600), (Some("SMB".r), None, None, Some("STATUS_INVALID_PARAMETER".r), Some("Trans2 Response".r), None, None))
      val s4 = new State("s4", "eternal", true, Nil, List("s3"), Map(), (Some("SMB".r), Some("82".r), None, Some("STATUS_NOT_IMPLEMENTED".r), Some("Trans2 Response".r), None, None))
      
      // Define the Eternal Blue attack pattern
      val eternal = new Pattern("eternal", "Testing for eternal blue exploit", Map("s0"->s0,"s1"->s1,"s2"->s2,"s3"->s3,"s4"->s4))

      val threadArray: Array[MyWorker] = new Array[MyWorker](noWorkers)
      val mod = new Model(Map("s0" -> smr), Map.empty[String, Double])
      for (i <- 0 until noWorkers) {
        threadArray(i) = new MyWorker(i, mod, eternal, noOutput, noWorkers)
        threadArray(i).setName(i.toString)
        threadArray(i).setPriority(10)
      }
      
      val startTimeM2 = System.nanoTime()
      for (t <- threadArray) t.start()
      for (t <- threadArray) t.join()
      val endTimeM2 = System.nanoTime()
      val e2 = (endTimeM2 - startTimeM2) / 1000000.0      
      
      val (finalS, finalT) = conc.getST

      if (! noCount) {
        for ((i, t) <- allTransitions.distinct.sorted) {
          transitionsCount = transitionsCount.updated(t, transitionsCount(t) + 1)
        }
      }
      


      //val keys: Set[String] = transitionsCount.keySet().asScala.toSet
      if (! noOutput) {
        for (k <- transitionsCount.keys.toList.sorted) {println(k + " {Occurance(s): " + transitionsCount(k) + ", First occurance: " + finalT.getOrElse(k, "N/A")+"}")}
        for (k <- finalS.keys.toList.sorted) {
          if (k != "s0") println(k + " {Last transition to: " + finalS(k).commitTime + "}")
          else println("s0 {Original state}")
        }
      }

      multiThreadTime = e2

    }

    def readDataIndex2(file: String, furthest: Int) : Vector[RawData] = {
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

      // Process data rows
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
      var outData = List.empty[RawData]
      while (revData != Nil) {
        val e = revData.head
        revData = revData.tail
        outData = (e.protocol, e.multiplex, e.length, e.nt, e.misc, e.time) +: outData
      }
      return(outData.toVector)
    }

    def getConcTrace(stateId1: String, model: ConcModel, attack: Pattern): List[String] = {
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
        if (model.transition(t) > ceilingTime) ceilingTime = model.transition(t);
      }

      while (true) {
        var validTransitions = List.empty[(String, String)];
        if (attack.s(stateId).parents == Nil) return result.reverse; // reached s0
        else {
          for (parent <- attack.s(stateId).parents) {
            validTransitions = (parent + ' ' + stateId, parent) :: validTransitions;
          }
        }

        if (validTransitions.isEmpty) return result.reverse;
        else {
          var targetTransition = validTransitions.head._1;
          var targetOriginal = validTransitions.head._2;
          for ((t, a) <- validTransitions) {
            if (model.transition(t) > model.transition(targetTransition) &&
              model.transition(t) < ceilingTime) {
              targetTransition = t;
              targetOriginal = a;
            }
          }
          if (model.transition(targetTransition) > ceilingTime) return result.reverse;
          else {
            result = targetOriginal :: result;
            stateId = targetOriginal; //traceDFS(transition.original)
            ceilingTime = transitions.map(t => model.transition(t)).max;
          }
        }
      }
      return result.reverse;
    }

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
        if (attack.s(stateId).parents == Nil) return result; // reached s0
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
            stateId = targetOriginal; //traceDFS(transition.original)
            ceilingTime = transitions.map(t => tModel(t)).max;
          }
        }
      }
      return result;
    }


    class TraceWorker(stateModel: Map[String, StateModelRecord], transitionModel: Map[String, Double], attack: Pattern, to: String, now: Double) extends Thread{
      override def run() = {
        //val updatedModel = new Model(stateModel, transitionModel);
        if (conc.traceCheck(to.tail.toInt)) {
          var current = getTrace(to, stateModel, transitionModel, attack)
          if (file == "Chen_2019.csv") print("Multithreaded alert for state \'" + to + "\' at log time 414.079367s, trace: ")
          else print("Multithreaded alert for state \'" + to + "\' at log time "+ now + "s, trace: ")
          while(current.tail != Nil) {
            print(current.head + " -> ")
            current = current.tail
          }
          println(current.head)
        }
      }
    }

    class MyWorker(wId: Int, model: Model, attack: Pattern, noOutput: Boolean, noWorkers: Int) extends Thread {
      override def run() = {
        val length = data.length
        var i = 0
        var m : Model = new Model(Map("s0" -> smr), Map("s0" -> 0.0)); //conc.getM
        var stateModel = model.state;
        var transitionModel = model.transition;
        var targetTransitions : List[Transition] = List();
        var timeoutTransitions : List[Transition] = List();
        var newTransitions : List[String] = List();
        var updatedModel : Model = null;
        var now = 0.0;
        var updated = false
        var newTraceList = ""
        var version = 0
        var bitSet = BitSet()
        while({val (i1, s1, t1, b1) = conc.incAndGetIM2; i = i1; stateModel = s1; transitionModel = t1; bitSet = b1; i < length}) {
          //println(i)
          updated = false
          newTransitions = Nil
          for ((t, s) <- stateModel) {
            for (c <- attack.s(s.id).children) {
              if (trigger(attack.s(c).triggerParams, data(i))) {
                if (!m.transition.contains(s.id +' ' + c)) {
                  now = data(i)._6
                  updated = true;
                  val t = new Transition(s.id, c)
                  if (now <= s.commitTime + attack.s(s.id).timeout(c)) {
                    // Keep first transition time
                    transitionModel = transitionModel + ((t.original + ' ' + t.to) -> transitionModel.getOrElse((t.original + ' ' + t.to), now))
                    // Update times
                    val update = new StateModelRecord(t.to, now);
                    stateModel = stateModel.updated(t.to, update);
                    newTransitions = (t.original + ' ' + t.to) :: newTransitions
                    if (attack.s(t.to).isOutput && ! noOutput) {
                      val trace = new TraceWorker(stateModel, transitionModel, attack, t.to, now)
                      trace.run()
                    }
                  }
                  else stateModel = stateModel - t.original;
                }
                //else println("blocked")
              }
            }
          }
          if (updated)  { 
            //val uM = new Model(stateModel, transitionModel)
            conc.rewind2(stateModel, transitionModel, i, newTransitions, bitSet); 
          }
        }
      }
    }

    def main(args : Array[String]) = {
      val arr = new Array[Double](1000)
      val file = args(1)
      data = readDataIndex2(file, 500000)

      val i = args(0).toInt
      concEternal2(i, false, false)
    }
  } 

  def main(args : Array[String]) = {
    file = args(1)
    val nArgs = Array(args(0), file)
    //println("Single Threaded:")
    //Run.main(nArgs);

    println("Multi Threaded")
    Run2.main(nArgs);

    //println("Single threaded time taken (ms): " + singleThreadTime")
    println("Multi threaded time taken (ms): " + multiThreadTime)
  }
}

