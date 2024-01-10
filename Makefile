crypt:
	python3 ./multi_protect.py -e ./data/duck.pdf ./data/duck_cypher.bin ./keys/senderPrivate.pem ./keys/senderPublic.pem ./keys/receiverPublic.pem ./keys/receiver2Public.pem

crypt-stream:
	python3 ./multi_protect_stream.py -e ./data/duck.pdf ./data/duck_cypher.bin ./keys/senderPrivate.pem ./keys/senderPublic.pem ./keys/receiverPublic.pem ./keys/receiver2Public.pem

cryptGPL:
	python3 ./multi_protect.py -e ./data/gpl.txt ./data/gpl_cypher.bin ./keys/senderPrivate.pem ./keys/senderPublic.pem ./keys/receiverPublic.pem ./keys/receiver2Public.pem

crypt2048:
	python3 ./multi_protect.py -e ./data/duck.pdf ./data/duck_cypher2048.bin ./keys/senderPrivate2048.pem ./keys/senderPublic2048.pem ./keys/receiverPublic2048.pem ./keys/receiver2Public2048.pem

decrypt:
	python3 ./multi_protect.py -d ./data/duck_cypher.bin ./data/duck_plain.pdf ./keys/receiverPrivate.pem ./keys/receiverPublic.pem ./keys/senderPublic.pem

decrypt-stream:
	python3 ./multi_protect_stream.py -d ./data/duck_cypher.bin ./data/duck_plain.pdf ./keys/receiverPrivate.pem ./keys/receiverPublic.pem ./keys/senderPublic.pem

decryptGPL:
	python3 ./multi_protect.py -d ./data/gpl_cypher.bin ./data/gpl_plain.txt ./keys/receiverPrivate.pem ./keys/receiverPublic.pem ./keys/senderPublic.pem

decrypt2:
	python3 ./multi_protect.py -d ./data/duck_cypher.bin ./data/duck_plain2.pdf ./keys/receiver2Private.pem ./keys/receiver2Public.pem ./keys/senderPublic.pem

decrypt2048:
	python3 ./multi_protect.py -d ./data/duck_cypher2048.bin ./data/duck_plain2048.pdf ./keys/receiverPrivate2048.pem ./keys/receiverPublic2048.pem ./keys/senderPublic2048.pem