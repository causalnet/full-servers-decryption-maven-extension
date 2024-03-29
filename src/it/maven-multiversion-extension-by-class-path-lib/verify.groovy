//Each different Maven version tested generated a different file name, check each one

['3.9.1', '3.8.7', '3.6.3' , '3.5.4', '3.3.9', '3.2.5'].each { mavenVersion ->

    //Check that the file downloaded by the dependency plugin using credentials from servers in settings.xml
    //that use username, password and token all encrypted which must be decrypted by our extension
    File downloadedFile = new File(basedir, "target/deps/testdata-${mavenVersion}.txt")
    assert downloadedFile.text.trim() == 'This is a text file dependency.'
}

return
