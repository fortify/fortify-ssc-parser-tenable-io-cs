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
import com.fortify.ssc.parser.tenable.io.cs.CustomVulnAttribute;
import com.fortify.ssc.parser.tenable.io.cs.domain.Finding;
import com.fortify.ssc.parser.tenable.io.cs.domain.NvdFinding;
import com.fortify.ssc.parser.tenable.io.cs.domain.Package;
import com.fortify.util.ssc.parser.EngineTypeHelper;
import com.fortify.util.ssc.parser.ScanDataStreamingJsonParser;
import com.fortify.util.ssc.parser.VulnerabilityBuilder;
import com.fortify.util.ssc.parser.VulnerabilityBuilder.CustomStaticVulnerabilityBuilder;

public class VulnerabilitiesParser {
	private static final String ENGINE_TYPE = EngineTypeHelper.getEngineType();
	private final ScanData scanData;
	private final VulnerabilityBuilder vulnerabilityBuilder;

    public VulnerabilitiesParser(final ScanData scanData, final VulnerabilityBuilder vulnerabilityBuilder) {
    	this.scanData = scanData;
		this.vulnerabilityBuilder = vulnerabilityBuilder;
	}
    
    /**
	 * Main method to commence parsing the SARIF document provided by the
	 * configured {@link ScanData}.
	 * @throws ScanParsingException
	 * @throws IOException
	 */
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.handler("/findings/*", Finding.class, this::buildVulnerability)
			.parse(scanData);
	}
	
    private final void buildVulnerability(Finding finding) {
    	NvdFinding nvdFinding = finding.getNvdFinding();
		
    	String cve = nvdFinding.getCve();
		String uniqueId = DigestUtils.sha256Hex(cve);
		CustomStaticVulnerabilityBuilder vb = vulnerabilityBuilder.startStaticVulnerability();
		// TODO For now we let CustomStaticVulnerabilityBuilder handle duplicate id's
		//      We should check whether there's a better way to generate unique id
		vb.setInstanceId(uniqueId);
		vb.setEngineType(ENGINE_TYPE);
		vb.setKingdom(FortifyKingdom.ENVIRONMENT.getKingdomName());
		vb.setAnalyzer(FortifyAnalyser.CONFIGURATION.getAnalyserName());
		vb.setCategory("Insecure Deployment");
		vb.setSubCategory("Vulnerable Container");
		
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
			vb.setStringCustomAttributeValue(CustomVulnAttribute.packages,
					Arrays.asList(packages).stream().map(Object::toString).collect(Collectors.joining("<br/>\n")));
		}
		
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
}
