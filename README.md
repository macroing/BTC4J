BTC4J
=====
BTC4J is a simple Bitcoin library for Java.

Getting Started
---------------
To clone this repository and build the project using Apache Ant, you can type the following in Git Bash.

```bash
git clone https://github.com/macroing/BTC4J.git
cd BTC4J
ant
```

Example
-------
The example below shows how an address can be obtained from a private key.

```java
import org.macroing.btc4j.Address;
import org.macroing.btc4j.PrivateKey;
import org.macroing.btc4j.PublicKey;

public class Example {
    public static void main(String[] args) {
        PrivateKey privateKey = PrivateKey.parseStringWIF("5J1F7GHadZG3sCCKHCwg8Jvys9xUbFsjLnGec4H125Ny1V9nR6V");
        
        PublicKey publicKey = privateKey.toPublicKey();
        
        boolean isCompressed = false;
        
        Address address = publicKey.toAddress(isCompressed);
        
        System.out.println(address);
    }
}
```

Dependencies
------------
 - [Java 8](http://www.java.com).

Note
----
This library has not reached version 1.0.0 and been released to the public yet. Therefore, you can expect that backward incompatible changes are likely to occur between commits. When this library reaches version 1.0.0, it will be tagged and available on the "releases" page. At that point, backward incompatible changes should only occur when a new major release is made.