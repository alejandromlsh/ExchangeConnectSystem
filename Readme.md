# First version.

Simply I will create a functional program, later I will increase performance.

One thing to do from the beginning is to use header only library files

I need the **pcap parser**, followed by **simba decoder** to read the payload data of the pcap file.
In particular **OrderUpdate**, **OrderExecution** and **OrderBookSnapshot**.

For the parsing I will start with zero copy memory mapped parsing from the beginning,