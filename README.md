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
```

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
