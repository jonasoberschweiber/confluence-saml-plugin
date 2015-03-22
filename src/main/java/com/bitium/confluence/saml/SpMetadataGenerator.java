/**
 * Confluence SAML Plugin - a confluence plugin to allow SAML 2.0
 *	authentication. 
 *
 *	Copyright (C) 2014 Bitium, Inc.
 *	
 *	This file is part of Confluence SAML Plugin.
 *	
 *	Confluence SAML Plugin is free software: you can redistribute it 
 *	and/or modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation, either version 3 of
 *	the License, or (at your option) any later version.
 *	
 *	Confluence SAML Plugin is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU General Public License
 *	along with Pineapple. If not, see <http://www.gnu.org/licenses/>.
 */
package com.bitium.confluence.saml;

import java.util.ArrayList;

import javax.servlet.ServletException;

import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.Configuration;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.springframework.security.saml.metadata.MetadataMemoryProvider;

import com.bitium.confluence.config.SAMLConfig;

public class SpMetadataGenerator {
	public MetadataProvider generate(SAMLConfig configuration) throws ServletException, MetadataProviderException {
		MetadataGenerator generator = new MetadataGenerator();
		generator.setKeyManager(new EmptyKeyManager());
		generator.setSignMetadata(false);
		
        // Defaults
        String alias = configuration.getAlias();
        String baseURL = configuration.getBaseUrl();

        generator.setEntityAlias(alias);
        generator.setEntityBaseURL(baseURL);
				ArrayList<String> ssoBindings = new ArrayList<String>();
				ssoBindings.add("post");
				generator.setBindingsSSO(ssoBindings);

        // Use default entityID if not set
        if (generator.getEntityId() == null) {
            generator.setEntityId(configuration.getSpEntityId());
        }
        
        Configuration.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager().getManager("MetadataKeyInfoGenerator");
        
        EntityDescriptor descriptor = generator.generateMetadata();
        ExtendedMetadata extendedMetadata = generator.generateExtendedMetadata();
        extendedMetadata.setRequireLogoutRequestSigned(false);

        MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor);
        memoryProvider.initialize();
        MetadataProvider spMetadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata);
        
        return spMetadataProvider;
	}
}
