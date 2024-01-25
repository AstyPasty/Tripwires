# Tripwires 3YP

A third year project completed by Thomas Aston under the supervision of Dr Louise Axon and Dr Ioannis Agrafiotis. This repo contains a cleaned up version of the code and the test files used in the paper (included in repo as Tripwires-3yp.pdf).

Any queries please contact thomas.aston@cs.ox.ac.uk

## `tripwiresChecker.scala`

This contains the tidied, corrected concurrent version of the detection system, making use of a range of concurrent datatypes provided by both Scala and Java. It can be compiled as normal using `fsc` and intended usage is as follows:

`scala TripwiresChecker n file`

where `n` is the number of workers to use and `file` is the filepath of the log file that is to be checked

### Recommended Changes

There are a few changes/additions that I would recommend that I did not have time to make/were outside the spec of what I was trying to do:

 - Add some method to allow the system to work with longer log files (currently limited by heap size). My current idea for this would be to read in and then process the first [0..n) lines of the log file, then the section from [n..2n), [2n..3n) and so on.
 - Some method of eternally storing and loading attack patterns; this should be quite straightforward if a specific format was defined so that they could stored/loaded from a file.
 - Change TraceWorker so that it always presents the first occurance of a transition to a final state, not just the first transition to be fully processed.
 - One potentially different approach to concurrency would be to have one worker per attack pattern; this would remove the need for rewinds and hence every single iteration is useful (instead of potentially being discarded) 
 - If keeping the current concurrency approach then some method of recycling threads would be beneficial; at the moment they terminate as soon as they receive suitably large $i$ regardless of whether further `rewind`s occur

### Concurrent Correctness

The safety invariant and methodology provided in the paper were insufficient; they allowed for an edge case race condition that would result in a transition being permanently overwritten by overlapping calls to `rewind`. This has been fixed by including the `BitSet`, which contains all the lines that a transition has occured on. A `rewind` is only allowed if its `BitSet` is equal to the central model in the range from $0$ to the index $1$ before the new transiion; this stops any transition at line $j$ from being added and then removed by a rewind that sets index to $k$ st. $j < k$.

## logs directory

This directory contains the `.csv` files used for testing the system against Eternal Blue; these were produced by taking the `.pcap` files associated with the relevant citations and then using Wireshark to convert the relevant data to `.csv` files. Further explanation can be found in section 5.2 of the paper