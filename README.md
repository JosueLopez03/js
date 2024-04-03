# CSCE3550_JWKS_JL
basic JWKS server: project3

##CSCE 3550 jl1201
Either download or copy or fork the repository to your system.
Open one terminal and ```cd``` into the "js" file,
then run ```npm install``` to download all necessary 
dependencies on your machine.

##Run server
To run the server ```cd``` into the "js" directory and run ```npm start```.
To quit the program run ```CONTROL+C```.

##Run server.test
To run the server.test start by opening two terminals.
```cd``` into the "js" directory on both terminals.
Run ```npm start``` on one terminal, make sure that it
is running without errors. On the other terminal run ```npm test```.
This will run the server.test file automatically, and 
quit after all tests are run. Make sure to quit the server
program after all test finish by running ```CONTROL+C```.

##Run GradeBot
To run the GradeBot program start by downloading or 
copying or forking the following grading repository
"https://github.com/HD1050/CSCE3550".
Make sure to have go.mod, go.sum, and main.go in the 
same directory as the file you want to test for grading.
Now after all files are in the same directory open two terminals.
```cd``` into the directory containing all files on both terminals.
Run ```npm start``` on one terminal, make sure that it
is running without errors. On the other terminal run
```go run main.go (here put the project type aka 'project1' 'project2' 'project3')```.
Because this is project three I will run
```go run main.go project3``` on the second terminal.
This will run gradebot, after all test are run press any key to quit. 
Finally, make sure to quit the server
program after all test finish by running ```CONTROL+C```.