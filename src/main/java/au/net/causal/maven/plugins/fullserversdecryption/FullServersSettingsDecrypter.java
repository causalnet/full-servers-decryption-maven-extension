package au.net.causal.maven.plugins.fullserversdecryption;

import com.google.inject.Inject;
import org.apache.maven.settings.Proxy;
import org.apache.maven.settings.Server;
import org.apache.maven.settings.building.DefaultSettingsProblem;
import org.apache.maven.settings.building.SettingsProblem;
import org.apache.maven.settings.crypto.DefaultSettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecrypter;
import org.apache.maven.settings.crypto.SettingsDecryptionRequest;
import org.apache.maven.settings.crypto.SettingsDecryptionResult;
import org.codehaus.plexus.component.annotations.Component;
import org.codehaus.plexus.util.xml.Xpp3Dom;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcher;
import org.sonatype.plexus.components.sec.dispatcher.SecDispatcherException;

import javax.inject.Named;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component(role = SettingsDecrypter.class)
public class FullServersSettingsDecrypter extends DefaultSettingsDecrypter
{
    private final SecDispatcher secDispatcher;

    @Inject
    public FullServersSettingsDecrypter(@Named("maven") SecDispatcher securityDispatcher)
    {
        super(securityDispatcher);
        this.secDispatcher = securityDispatcher;
    }

    @Override
    public SettingsDecryptionResult decrypt(SettingsDecryptionRequest request)
    {
        SettingsDecryptionResult result =  super.decrypt(request);
        performFullServerDecryption(result.getServers(), result.getProblems());
        performFullProxyDecryption(result.getProxies(), result.getProblems());

        List<Server> requestServersToDecrypt = request.getServers().stream()
                                                                   .filter(s -> readConfiguration(s).isPersistDecryptionInMemory())
                                                                   .collect(Collectors.toList());
        if (!requestServersToDecrypt.isEmpty())
            performFullServerDecryption(requestServersToDecrypt, result.getProblems());


        return result;
    }

    private ServerConfiguration readConfiguration(Server server)
    {
        ServerConfiguration config = new ServerConfiguration();

        if (server.getConfiguration() instanceof Xpp3Dom)
        {
            Xpp3Dom serverConfigXml = (Xpp3Dom)server.getConfiguration();
            Xpp3Dom fullServersConfigXml = serverConfigXml.getChild("fullServersDecryption");

            //Could use configurators but for one field seems overkill

            if (fullServersConfigXml != null)
            {
                Xpp3Dom persistDecryptionInMemoryXml = fullServersConfigXml.getChild("persistDecryptionInMemory");
                if (persistDecryptionInMemoryXml != null && persistDecryptionInMemoryXml.getValue() != null)
                    config.setPersistDecryptionInMemory(Boolean.parseBoolean(persistDecryptionInMemoryXml.getValue()));
            }
        }

        return config;

    }

    private void performFullProxyDecryption(Collection<? extends Proxy> proxies, Collection<? super SettingsProblem> problems)
    {
        for (Proxy proxy : proxies)
        {
            String proxyId = proxy.getId();
            performDecryption(proxyId, "proxy", "username", proxy::getUsername, proxy::setUsername, problems);
            performDecryption(proxyId, "proxy", "password", proxy::getPassword, proxy::setPassword, problems);
            performDecryption(proxyId, "proxy", "protocol", proxy::getProtocol, proxy::setProtocol, problems);
            performDecryption(proxyId, "proxy", "host", proxy::getHost, proxy::setHost, problems);
            performDecryption(proxyId, "proxy", "nonProxyHosts", proxy::getNonProxyHosts, proxy::setNonProxyHosts, problems);
        }
    }

    private void performFullServerDecryption(Collection<? extends Server> servers, Collection<? super SettingsProblem> problems)
    {
        for (Server server : servers)
        {
            String serverId = server.getId();
            performDecryption(serverId, "server", "username", server::getUsername, server::setUsername, problems);
            performDecryption(serverId, "server", "password", server::getPassword, server::setPassword, problems);
            performDecryption(serverId, "server", "passphrase", server::getPassphrase, server::setPassphrase, problems);
            performDecryption(serverId, "server", "privateKey", server::getPrivateKey, server::setPrivateKey, problems);
            performDecryption(serverId, "server", "filePermissions", server::getFilePermissions, server::setFilePermissions, problems);
            performDecryption(serverId, "server", "directoryPermissions", server::getDirectoryPermissions, server::setDirectoryPermissions, problems);

            Object config = server.getConfiguration();

            if (config != null)
            {
                if (config instanceof Xpp3Dom)
                {
                    Xpp3Dom xml = (Xpp3Dom) config;
                    decryptXml(serverId, "configuration", xml, problems);
                }
            }
        }
    }

    private void decryptXml(String serverId, String propertyName, Xpp3Dom xmlElement, Collection<? super SettingsProblem> problems)
    {
        if (xmlElement.getValue() != null)
            performDecryption(serverId, "server", propertyName, xmlElement::getValue, xmlElement::setValue, problems);

        Xpp3Dom[] children = xmlElement.getChildren();
        if (children != null)
        {
            for (Xpp3Dom child : children)
            {
                decryptXml(serverId, propertyName + "." + child.getName(), child, problems);
            }
        }
    }

    private void performDecryption(String entryId, String serverOrProxy, String propertyName, Supplier<String> getter, Consumer<String> setter, Collection<? super SettingsProblem> problems)
    {
        String raw = getter.get();
        if (raw != null)
        {
            try
            {
                String decrypted = secDispatcher.decrypt(raw);
                setter.accept(decrypted);
            }
            catch (SecDispatcherException e)
            {
                problems.add(new DefaultSettingsProblem("Failed to decrypt " + propertyName + " for " + serverOrProxy + " " + entryId
                                                        + ": " + e.getMessage(), SettingsProblem.Severity.ERROR, serverOrProxy + ": " + entryId, -1, -1, e ) );
            }
        }
    }

    private static class ServerConfiguration
    {
        private boolean persistDecryptionInMemory;

        public boolean isPersistDecryptionInMemory()
        {
            return persistDecryptionInMemory;
        }

        public void setPersistDecryptionInMemory(boolean persistDecryptionInMemory)
        {
            this.persistDecryptionInMemory = persistDecryptionInMemory;
        }
    }
}
