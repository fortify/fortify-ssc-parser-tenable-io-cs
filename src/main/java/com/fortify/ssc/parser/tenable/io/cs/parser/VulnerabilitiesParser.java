package com.fortify.ssc.parser.tenable.io.cs.parser;

import java.io.IOException;
import java.math.BigDecimal;

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
import com.fortify.ssc.parser.tenable.io.cs.domain.NvdFindingPackage;
import com.fortify.ssc.parser.tenable.io.cs.parser.util.Constants;
import com.fortify.util.ssc.parser.ScanDataStreamingJsonParser;
import com.fortify.util.ssc.parser.VulnerabilityBuilder;
import com.fortify.util.ssc.parser.VulnerabilityBuilder.CustomStaticVulnerabilityBuilder;

public class VulnerabilitiesParser {
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
			.handler("/findings/*", Finding.class, this::handleFinding)
			.parse(scanData);
	}
	
    private final void handleFinding(Finding finding) {
		NvdFindingPackage[] packages = finding.getPackages();
		if ( packages!=null && packages.length>0 ) {
			for ( NvdFindingPackage pkg : packages ) {
				buildVulnerability(finding.getNvdFinding(), pkg);
			}
		}
    }
    
    private final void buildVulnerability(NvdFinding finding, NvdFindingPackage pkg) {
    	String pkgName = pkg.getName();
    	String cve = finding.getCve();
		String uniqueId = DigestUtils.sha256Hex(cve+"-"+pkgName);
		CustomStaticVulnerabilityBuilder vb = vulnerabilityBuilder.startStaticVulnerability();
		// TODO For now we let CustomStaticVulnerabilityBuilder handle duplicate id's
		//      We should check whether there's a better way to generate unique id
		vb.setInstanceId(uniqueId);
		vb.setEngineType(Constants.ENGINE_TYPE);
		vb.setKingdom(FortifyKingdom.ENVIRONMENT.getKingdomName());
		vb.setAnalyzer(FortifyAnalyser.CONFIGURATION.getAnalyserName());
		vb.setCategory("Insecure Deployment");
		vb.setSubCategory("Vulnerable Container");
		
		vb.setStringCustomAttributeValue(CustomVulnAttribute.pkg, pkg.getName()+" "+pkg.getVersion());
		vb.setDateCustomAttributeValue(CustomVulnAttribute.publishedDate, finding.getPublished_date());
		vb.setDateCustomAttributeValue(CustomVulnAttribute.modifiedDate, finding.getModified_date());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cve, finding.getCve());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cveUrl, "https://nvd.nist.gov/vuln/detail/"+finding.getCve());
		
		// Set mandatory values to JavaDoc-recommended values
		vb.setAccuracy(5.0f);
		vb.setConfidence(2.5f);
		vb.setLikelihood(2.5f);
		
		vb.setFileName(pkgName);
		vb.setVulnerabilityAbstract(finding.getDescription());
		
		Float cvvsScore = finding.getCvss_score();
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
		
		String cwe = finding.getCwe();
		if ( StringUtils.isNotBlank(cwe) ) {
			// TODO Should this allow us to group by CWE in SSC? Doesn't currently work.
			vb.setMappedCategory(cwe.replace("CWE-", "CWE ID "));
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cwe, String.join(", ", cwe));
		}
		
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAccessVector, finding.getAccess_vector());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAccessComplexity, finding.getAccess_complexity());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssConfidentialityImpact, finding.getConfidentiality_impact());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssIntegrityImpact, finding.getIntegrity_impact());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAvailabilityImpact, finding.getAvailability_impact());
		
		vb.completeVulnerability();
    }
}
