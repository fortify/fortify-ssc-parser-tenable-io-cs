package com.fortify.ssc.parser.tenable.io.cs.parser;

import java.io.IOException;

import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanEntry;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.util.jackson.IsoDateTimeConverter;
import com.fortify.util.ssc.parser.json.ScanDataStreamingJsonParser;

public class ScanParser {
	private final ScanData scanData;
	private final ScanEntry scanEntry;
    private final ScanBuilder scanBuilder;
    
	public ScanParser(final ScanData scanData, final ScanEntry scanEntry, final ScanBuilder scanBuilder) {
		this.scanData = scanData;
		this.scanEntry = scanEntry;
		this.scanBuilder = scanBuilder;
	}
	
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.handler("/updated_at", jp -> scanBuilder.setScanDate(IsoDateTimeConverter.getInstance().convert(jp.getValueAsString())))
			.handler("/image_name", jp -> scanBuilder.setBuildId(jp.getValueAsString()))
			.handler("/tag", jp -> scanBuilder.setScanLabel(jp.getValueAsString()))
			.handler("/installed_packages", jp -> scanBuilder.setNumFiles(jp.countArrayEntries()))
			.parse(scanData, scanEntry);
		scanBuilder.setEngineVersion("Unknown");
		scanBuilder.completeScan();
	}
}
