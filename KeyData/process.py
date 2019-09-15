a = open("data_client.txt");
while 1:
	line = a.readline().strip()
	if not line:
		break
	print (len(line.split(' ')))
	break

	
