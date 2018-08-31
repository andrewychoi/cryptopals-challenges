
def main():
	lines = []
	with open("7.txt") as infile:
		for line in infile:
			lines.append(line)
	print(lines) 
	provided_key = "YELLOW SUBMARINE"
	print(provided_key)

if __name__ == "__main__":
	main()