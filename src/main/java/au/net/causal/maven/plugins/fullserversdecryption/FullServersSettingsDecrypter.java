package au.net.causal.maven.plugins.fullserversdecryption;

import com.google.inject.Inject;
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
        //TODO ability to save back to original request server objects (opt-in)
        performAdditionalDecryption(result);
        return result;
    }

    private void performAdditionalDecryption(SettingsDecryptionResult result)
    {
        for (Server server : result.getServers())
        {
            List<SettingsProblem> problems = result.getProblems();
            String serverId = server.getId();
            performDecryption(serverId, "username", server::getUsername, server::setUsername, problems);
            performDecryption(serverId, "password", server::getPassword, server::setPassword, problems);
            performDecryption(serverId, "passphrase", server::getPassphrase, server::setPassphrase, problems);
            performDecryption(serverId, "privateKey", server::getPrivateKey, server::setPrivateKey, problems);
            performDecryption(serverId, "filePermissions", server::getFilePermissions, server::setFilePermissions, problems);
            performDecryption(serverId, "directoryPermissions", server::getDirectoryPermissions, server::setDirectoryPermissions, problems);

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
            performDecryption(serverId, propertyName, xmlElement::getValue, xmlElement::setValue, problems);

        Xpp3Dom[] children = xmlElement.getChildren();
        if (children != null)
        {
            for (Xpp3Dom child : children)
            {
                decryptXml(serverId, propertyName + "." + child.getName(), child, problems);
            }
        }
    }

    private void performDecryption(String serverId, String propertyName, Supplier<String> getter, Consumer<String> setter, Collection<? super SettingsProblem> problems)
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
                problems.add(new DefaultSettingsProblem("Failed to decrypt " + propertyName + " for server " + serverId
                                                        + ": " + e.getMessage(), SettingsProblem.Severity.ERROR, "server: " + serverId, -1, -1, e ) );
            }
        }
    }
}
