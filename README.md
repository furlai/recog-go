# Recog-Go: Pattern Recognition using Rapid7 Recog

This is a Go implementation of the [Recog](https://github.com/rapid7/recog/) library and fingerprint database from Rapid7.

This package requires a checkout of the recog repository in order to build.

Recog-Go is open source, please see the [LICENSE](https://raw.githubusercontent.com/runZeroInc/recog-go/master/LICENSE) file for more information.

The [recog_match](cmd/recog_match/main.go) utility contains a working example

To build and install:
```
$ git clone https://github.com/rapid7/recog.git /path/to/recog
$ RECOG_XML=/path/to/recog/xml go generate
$ go install . ./cmd/...
```

## Testing with furlai/recog-xml fingerprint database

Set FINGERPRINT_TEXT env with text of the fingerprint to match against, and run:
```
export FINGERPRINT_TEXT='<p><p>Vulnerable software installed: Apache Commons Text 1.9 (/System/Volumes/Data/Users/zyoutz/workspace/vulnerable_software/neo4j-enterprise-4.3.7/lib/commons-text-1.9.jar)</p><p>Vulnerable version of Apache Commons Text detected.</p></p>'
```

Run recog_match_graph:
```
echo $FINGERPRINT_TEXT | go run cmd/recog_match_graph/main.go --root ../recog-xml -m rapid7.ivm.prooftext

****** Best Matches ******
Matched: Rapid7 InsightVM Proof: Software with path
  Id: 8e1fb806-daab-4f87-b584-acd925ca229d
  Type: rapid7.ivm.proof.software
  Values:
    fp.certainty: 0.85
    fs.file: /System/Volumes/Data/Users/zyoutz/workspace/vulnerable_software/neo4j-enterprise-4.3.7/lib/commons-text-1.9.jar
    rapid7.ivm.proof.swdesc: Apache Commons Text 1.9

Matched: Generic Apache software fingerprint from InsightVM
  Id: b18c3c65-f5f1-4da2-bc44-d25298fa4eda
  Type: software
  Values:
    fp.certainty: 0.5
    software.product: Commons Text
    software.vendor: Apache Software Foundation
    software.version: 1.9

Matched: Apple filesystem system-wide software package fingerprint
  Id: 7911bbea-663e-44f0-9b84-f2832cccb5e5
  Type: software.package
  Values:
    fp.certainty: 0.3
    software.package.installpath: /Users/zyoutz/workspace/vulnerable_software/neo4j-enterprise-4.3.7/lib/commons-text-1.9.jar
    software.package.name: unknown
    software.package.scope: system
    software.package.vendor : unknown

****** Rejected Matches ******
Matched: Generic software with optional version from InsightVM
  Id: 0721230f-88ff-444d-bd19-a6e61b103466
  Type: software
  Values:
    fp.certainty: 0.45
    software.product: Apache Commons Text
    software.version: 1.9

Matched: Generic software fingerprint from InsightVM
  Id: 8b4f617b-7fa4-4433-8860-124eb9b5c986
  Type: software
  Values:
    fp.certainty: 0.4
    software.product: Apache Commons Text 1.9

****** Tree ******
Input: <p><p>Vulnerable software installed: Apache Commons Text 1.9 (/System/...
└── [ivm_proof.xml]  Rapid7 InsightVM Proof: Software with path
    ├── [ivm_proof_sw_desc.xml]  Generic Apache software fingerprint from InsightVM
    ├── [ivm_proof_sw_desc.xml]  Generic software with optional version from InsightVM
    ├── [ivm_proof_sw_desc.xml]  Generic software fingerprint from InsightVM
    └── [fs_file_packagemanager.xml]  Apple filesystem system-wide software package fingerprint
```

NOTE: furl currently uses the highest fp.certainty for both type `software` and `software.package`.

## Example proofs from InsightVM

Apache Commons Text:
```
export FINGERPRINT_TEXT='<p><p>Vulnerable software installed: Apache Commons Text 1.9 (/System/Volumes/Data/Users/zyoutz/workspace/vulnerable_software/neo4j-enterprise-4.3.7/lib/commons-text-1.9.jar)</p><p>Vulnerable version of Apache Commons Text detected.</p></p>'
```

Firefox (non-standard location):
```
export FINGERPRINT_TEXT='<p><p>Vulnerable software installed: Mozilla Firefox 117.0.1 (/Users/zyoutz2/Documents/Firefox.app)</p></p>'
```

Firefox (standard location):
```
export FINGERPRINT_TEXT='<p><p>Vulnerable software installed: Mozilla Firefox 117.0.1 (/Applications/Firefox.app)</p></p>'
```

OpenJDK (homebrew):
```
export FINGERPRINT_TEXT='<p><p>Vulnerable OS: Apple Mac OS X 14.6.1.23G93<p></p></p><p>Vulnerable software installed: Azul Systems JRE 11.0.24 (/System/Volumes/Data/opt/homebrew/Cellar/openjdk@11/11.0.24/libexec/openjdk.jdk/Contents/Home/lib/jrt-fs.jar)</p></p>'
```
