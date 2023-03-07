# Full Servers Decryption Maven Extension

An extension for Maven that decrypts all elements of `<server>` entries in `settings.xml`, 
not just passwords and passphrases.  It allows other elements to be encrypted, such as
usernames and other configuration such as HTTP header values.

Standard Maven behaviour when 
[encrypting server entries](https://maven.apache.org/guides/mini/guide-encryption.html#How_to_encrypt_server_passwords) 
is to only decrypt [passwords and passphrases](https://maven.apache.org/settings.html#servers) from
each server entry.  This extension allows using encryption on any part of a server entry, 
including usernames and extra configuration such as 
[HTTP headers](https://maven.apache.org/guides/mini/guide-http-settings.html#http-headers).
This can be useful if you want to encrypt headers such as tokens which may be used for 
authentication with [Gitlab for example](https://docs.gitlab.com/ee/user/packages/maven_repository/#edit-the-settingsxml).

This extension also allows almost any field of 
[proxy configuration](https://maven.apache.org/guides/mini/guide-proxies.html) 
to be encrypted/decrypted in the same way, with the exception of `port` and `active` fields 
(due to these having non-string types in the Maven model).

## Requirements

- Maven 3.x
- Java 11 or later

## Installation

The extension needs to be downloaded and registered with Maven as an extension.

### Downloading

This can be done easily through Maven itself, downloading the extension Maven Central to your
local repository with:

```
mvn dependency:get -Dartifact=au.net.causal.maven.plugins:full-servers-decryption-maven-extension:1.0
```

### Registering the extension

The easiest and least invasive way of registering the extension is modifying the `MAVEN_OPTS`
environment variable to contain:

```
-Dmaven.ext.class.path=<your m2 directory>/repository/au/net/causal/maven/plugins/full-servers-decryption-maven-extension/1.0/full-servers-decryption-maven-extension-1.0.jar
```

If you already have `maven.ext.class.path` set up in `MAVEN_OPTS`, add this extension to the end with
your platform's path separator (';' on Windows, ':' on Mac/Linux).

Alternatively, you can copy the extension's JAR file into your Maven installation's `lib/ext` directory,
but this installs it globally for all users.

## Usage 

Once the extension is registered use encryption in any part of a server entry in 
your `settings.xml` file.  For example:

```
...
<server>
    <id>security-test-repo</id>
    <username>{QkIYOMfRMn4Hq7pPWjn3xnwt/vTpROj5n4H26IH9agQ=}</username>
    <password>{EObV8XZA4koHsufCpGMmjy1SlPt9D0aGjN6O+xq/Y+Q=}</password>
    <configuration>
        <httpHeaders>
            <property>
                <name>Auth-Token</name>
                <value>{nEJsVa63CW4HX22CWhj+xklNxrhtceGJC6B6pubztCw=}</value>
            </property>
        </httpHeaders>
    </configuration>
</server>
...
```

### Persisting decryption in memory

Some Maven plugins and extensions try to use server and proxy entries but do not perform
decryption properly or at all.  This extension can work around this problem by 
optionally saving the decrypted values back to memory so subsequent accesses will be able
to read the unencrypted value.  This is only done in-memory and not persisted to disk.

This may be activated for individual server entries by adding the following configuration:

```
<server>
...
    <configuration>        
        <fullServersDecryption>
            <persistDecryptionInMemory>true</persistDecryptionInMemory>
        </fullServersDecryption>
    </configuration>
</server>
```

This feature is normally not required unless you are using another buggy plugin/extension
that is not decrypting server entries properly.

## Building

To build the project, run:

```
mvn clean install
```
