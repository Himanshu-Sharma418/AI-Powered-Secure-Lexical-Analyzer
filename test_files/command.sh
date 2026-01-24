# System command examples
echo "Hello World";
system("ls -la");
exec("cat /etc/passwd");

# Potential malicious commands
echo $(cat /etc/shadow);
system('rm -rf /');
eval("malicious_code()");

# Chained commands
print "test"; system("whoami"); echo "done";