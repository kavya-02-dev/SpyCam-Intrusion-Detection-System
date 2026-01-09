Set shell = CreateObject("Shell.Application")
' Get the path to the batch file from the command line arguments (Arg(0))
batchFilePath = WScript.Arguments(0)
' Get the current working directory where the Python script is running
currentDir = WScript.Arguments(1)

' Use the Shell object to Run the command with elevated privileges
' The "cmd.exe /c" executes the batch file, and "runas" forces the UAC prompt.
shell.ShellExecute "cmd.exe", "/c """ & batchFilePath & """", currentDir, "runas", 1 

' This script terminates immediately after launching the elevated process.
