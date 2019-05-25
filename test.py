
string = "www_12-3.com"
print ''.join(e for e in string if e.isalnum() or e in '._-')