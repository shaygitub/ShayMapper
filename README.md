# ShayMapper
ShayMapper is an addition above the kdmapper project to make it alot easier to integrate different vulnerable drivers for the end
result of loading an unsigned driver into the memory. if the specific needed operations (i.e IOCTL-controlled memory copy) are not implemented
by any additional driver, they will be implemented automatically by the regular intel driver as it implements all operations.

to add a new driver for the loading process you will need to do the following:
1) create the needed IOCTL trigger functions by the needed format for each operation in TriggerOperations
2) Implement a Load() function that will register all needed trigger functions, create a file for the driver (either from memory buffer
   or in another way) and get a handle to the file that will be returned
3) add the handle to the array of running drivers, increment the count of running drivers and add the running driver index for each implemented operation
