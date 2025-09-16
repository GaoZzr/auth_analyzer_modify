package com.protect7.authanalyzer.controller;

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class HttpListener implements IHttpListener, IProxyListener {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		// Analyze exactly once per exchange:
		// - Normal mode: analyze on response (messageIsRequest == false) so we have the original response
		// - Drop-original mode: analyze on request (no original response will arrive)
		if(config.isRunning()) {
			boolean shouldAnalyze = false;
			if (!messageIsRequest) {
				// Always analyze on response in normal mode
				shouldAnalyze = true;
			}
			else if (messageIsRequest && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && config.isDropOriginal()) {
				// If we drop original, there will be no response; analyze at request time
				shouldAnalyze = true;
			}
			if(shouldAnalyze && !isFiltered(toolFlag, messageInfo)) {
				config.performAuthAnalyzerRequest(messageInfo);
			}
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if(config.isDropOriginal() && messageIsRequest) {
			// Analysis is handled by IHttpListener.processHttpMessage to avoid duplicate processing.
			// Here we only drop the original request if it would not be filtered.
			if(!isFiltered(IBurpExtenderCallbacks.TOOL_PROXY, message.getMessageInfo())) {
				message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
			}
		}
	}
	
	private boolean isFiltered(int toolFlag, IHttpRequestResponse messageInfo) {
		boolean isFiltered = false;
		IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
		IResponseInfo responseInfo = null;
		if(messageInfo.getResponse() != null) {
			responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		}
		for(int i=0; i<config.getRequestFilterList().size(); i++) {
			RequestFilter filter = config.getRequestFilterAt(i);
			if(filter.filterRequest(BurpExtender.callbacks, toolFlag, requestInfo, responseInfo)) {
				return true;
			}
		}
		return isFiltered;
	}
}
