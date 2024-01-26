# ShayMapper
ShayMapper is a major part of my windows rootkit project that is used to map my main KMDF driver stealthly and can be used to map other drivers.

Inspirations and helpful content:
kdmapper - used the general business logic of kdmapper for this project with some changes by my specific needs (i.e creating the vulnurable driver file in relative path of running)
LOLdrivers - i wanted to "add some flavor" to the vulnurable drivers exploitation used for loading the driver in kdmapper and this repository really helped in the process

P.S: mapping drivers with this mapper (like kdmapper) will get you PASSIVE_LEVEL IRQL, so if you need to get higher IRQL - make sure you use the WINAPI functions 
