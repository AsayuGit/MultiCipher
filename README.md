# MultiCipher

A tool to securly share files across multiple recipients.

[![GPLv2 License](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://opensource.org/licenses/)

## Usage/Examples

#### Syntax
```bash
  python3 ./multi_protect: [-e/-d] [keys] [recipients]
```

#### Exemple
```bash
  EG: python3 ./multi_protect.py -e ./data/gpl.txt ./data/gpl_cypher.bin ./keys/senderPrivate.pem ./keys/senderPublic.pem ./keys/receiverPublic.pem ./keys/receiver2Public.pem
```

#### Options
|  Option   | Description                                     |
| :-------- | :---------------------------------------------- |
| `-e`      | Encrypt a file for a set of recipients          |
| `-d`      | Decrypt a for encrypted for a recipient         |

#### Notes

"multi_protect_stream.py" Is functionaly the same as "multi_protect.py" but stream the file from disk rather than loading the whole file in memory.

This allows MultiCipher to process much larger files

## Authors

- [@AsayuGit](https://github.com/AsayuGit)