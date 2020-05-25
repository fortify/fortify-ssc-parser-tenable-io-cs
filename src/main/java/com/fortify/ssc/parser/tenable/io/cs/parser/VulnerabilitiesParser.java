package com.fortify.ssc.parser.tenable.io.cs.parser;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import com.fortify.plugin.api.BasicVulnerabilityBuilder.Priority;
import com.fortify.plugin.api.FortifyAnalyser;
import com.fortify.plugin.api.FortifyKingdom;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.ssc.parser.tenable.io.cs.CustomVulnAttribute;
import com.fortify.ssc.parser.tenable.io.cs.domain.Finding;
import com.fortify.ssc.parser.tenable.io.cs.domain.NvdFinding;
import com.fortify.ssc.parser.tenable.io.cs.domain.Package;
import com.fortify.util.ssc.parser.EngineTypeHelper;
import com.fortify.util.ssc.parser.HandleDuplicateIdVulnerabilityHandler;
import com.fortify.util.ssc.parser.ScanDataStreamingJsonParser;

public class VulnerabilitiesParser {
	private static final String ENGINE_TYPE = EngineTypeHelper.getEngineType();
	private final ScanData scanData;
	private final VulnerabilityHandler vulnerabilityHandler;

    public VulnerabilitiesParser(final ScanData scanData, final VulnerabilityHandler vulnerabilityHandler) {
    	this.scanData = scanData;
		this.vulnerabilityHandler = new HandleDuplicateIdVulnerabilityHandler(vulnerabilityHandler);
	}
    
    /**
	 * Main method to commence parsing the input provided by the configured {@link ScanData}.
	 * @throws ScanParsingException
	 * @throws IOException
	 */
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.handler("/findings/*", Finding.class, this::buildVulnerabilityIfValid)
			.parse(scanData);
	}
	
	/**
	 * Call the {@link #buildVulnerability(Finding)} method if the given {@link Finding}
	 * provides valid vulnerability data.
	 * @param finding
	 */
	private final void buildVulnerabilityIfValid(Finding finding) {
		if ( finding!=null && finding.getNvdFinding()!=null && StringUtils.isNotBlank(finding.getNvdFinding().getCve()) ) {
			buildVulnerability(finding);
		}
	}
	
	/**
	 * Build the vulnerability from the given {@link Finding}, using the configured {@link VulnerabilityHandler}.
	 * @param finding
	 */
    private final void buildVulnerability(Finding finding) {
		StaticVulnerabilityBuilder vb = vulnerabilityHandler.startStaticVulnerability(getInstanceId(finding));
		NvdFinding nvdFinding = finding.getNvdFinding();
		String cve = nvdFinding.getCve();
		
		vb.setEngineType(ENGINE_TYPE);
		vb.setKingdom(FortifyKingdom.ENVIRONMENT.getKingdomName());
		vb.setAnalyzer(FortifyAnalyser.CONFIGURATION.getAnalyserName());
		vb.setCategory("Insecure Deployment");
		vb.setSubCategory("Unpatched Application");
		
		vb.setDateCustomAttributeValue(CustomVulnAttribute.publishedDate, nvdFinding.getPublished_date());
		vb.setDateCustomAttributeValue(CustomVulnAttribute.modifiedDate, nvdFinding.getModified_date());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cve, cve);
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cveUrl, "https://nvd.nist.gov/vuln/detail/"+cve);
		
		// Set mandatory values to JavaDoc-recommended values
		vb.setAccuracy(5.0f);
		vb.setConfidence(2.5f);
		vb.setLikelihood(2.5f);
		
		Package[] packages = finding.getPackages();
		if ( packages!=null && packages.length>0 ) {
			vb.setFileName(packages[0].getName());
		}
		vb.setStringCustomAttributeValue(CustomVulnAttribute.packages, getPackagesAsString(packages, "<br/>\n"));
		
		vb.setVulnerabilityAbstract(nvdFinding.getDescription());
		
		Float cvvsScore = nvdFinding.getCvss_score();
		if ( cvvsScore==null ) {
			vb.setPriority(Priority.Medium);
		} else {
			vb.setDecimalCustomAttributeValue(CustomVulnAttribute.cvssScore, new BigDecimal(cvvsScore.toString()));
			if ( cvvsScore < 3.9f ) {
				vb.setPriority(Priority.Low);
			} else if ( cvvsScore < 6.9f ) {
				vb.setPriority(Priority.Medium);
			} else if ( cvvsScore < 8.9f ) {
				vb.setPriority(Priority.High);
			} else {
				vb.setPriority(Priority.Critical);
			}
		}
		
		String cwe = nvdFinding.getCwe();
		if ( StringUtils.isNotBlank(cwe) ) {
			// TODO Should this allow us to group by CWE in SSC? Doesn't currently work.
			vb.setMappedCategory(cwe.replace("CWE-", "CWE ID "));
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cwe, String.join(", ", cwe));
		}
		
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAccessVector, nvdFinding.getAccess_vector());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAccessComplexity, nvdFinding.getAccess_complexity());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssConfidentialityImpact, nvdFinding.getConfidentiality_impact());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssIntegrityImpact, nvdFinding.getIntegrity_impact());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAvailabilityImpact, nvdFinding.getAvailability_impact());
		
		vb.completeVulnerability();
    }

    /**
     * Get the list of packages as a String
     * @param packages
     * @param delimiter
     * @return
     */
	private final String getPackagesAsString(Package[] packages, String delimiter) {
		return (packages==null || packages.length==0 ) 
			? "<none>"
			: Arrays.asList(packages).stream().map(Object::toString).sorted().collect(Collectors.joining(delimiter));
	}

	/**
	 * Calculate the issue instance id, using a combination of all package names, types and versions, and CVE name
	 */
	private final String getInstanceId(Finding finding) {
		NvdFinding nvdFinding = finding.getNvdFinding();
		Package[] packages = finding.getPackages();
		return DigestUtils.sha256Hex(String.format("%s|%s", getPackagesAsString(packages, "+"), nvdFinding.getCve()));
	}
}
