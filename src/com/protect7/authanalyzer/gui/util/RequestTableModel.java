package com.protect7.authanalyzer.gui.util;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Set;
// removed unused digest imports
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.RequestSignatureHelper;

public class RequestTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final ArrayList<OriginalRequestResponse> originalRequestResponseList = new ArrayList<OriginalRequestResponse>();
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final int STATIC_COLUMN_COUNT = 8;
	// Signatures muted (tombstoned) by user deletion so duplicates remain hidden
	private final Set<String> mutedSignatures = new HashSet<String>();
	
	public ArrayList<OriginalRequestResponse> getOriginalRequestResponseList() {
		return originalRequestResponseList;
	}
	
	public synchronized void addNewRequestResponse(OriginalRequestResponse requestResponse) {
		// Always check for same path and set comment ID if found, regardless of signature duplication
		try {
			String pathOnly = extractPathOnly(requestResponse.getUrl());
			Integer representativeId = findFirstVisibleRepresentativeIdForPath(pathOnly);
			if (representativeId != null) {
				requestResponse.setComment("重复ID:" + representativeId);
			} else {
				requestResponse.setComment("");
			}
		}
		catch (Exception e) {
			// ignore
		}
		originalRequestResponseList.add(requestResponse);
		final int index = originalRequestResponseList.size()-1;
		SwingUtilities.invokeLater(new Runnable() {
			
			@Override
			public void run() {
				fireTableRowsInserted(index, index);
			}
		});
	}

	private String extractPathOnly(String url) {
		if (url == null) {
			return "";
		}
		String pathOnly = url;
		int q = url.indexOf('?');
		if (q >= 0) {
			pathOnly = url.substring(0, q);
		}
		if (pathOnly.length() > 1 && pathOnly.endsWith("/")) {
			pathOnly = pathOnly.substring(0, pathOnly.length() - 1);
		}
		return pathOnly;
	}

	// Returns the first visible representative id for the given path (ignoring query),
	// skipping entries that are effectively hidden by folding (earlier same signature)
	// or muted by user deletion.
	private Integer findFirstVisibleRepresentativeIdForPath(String pathOnly) {
		Integer bestId = null;
		for (OriginalRequestResponse existing : originalRequestResponseList) {
			String existingPath = extractPathOnly(existing.getUrl());
			if (!existingPath.equals(pathOnly)) {
				continue;
			}
			try {
				String sig = RequestSignatureHelper.computeMultiDimSignature(existing);
				// Skip if muted
				if (mutedSignatures.contains(sig)) {
					continue;
				}
				// Skip if there exists an even earlier same-signature entry (folded)
				boolean foldedByEarlierSameSig = false;
				for (OriginalRequestResponse prev : originalRequestResponseList) {
					if (prev.getId() < existing.getId()) {
						String prevSig = RequestSignatureHelper.computeMultiDimSignature(prev);
						if (sig.equals(prevSig)) {
							foldedByEarlierSameSig = true;
							break;
						}
					}
				}
				if (foldedByEarlierSameSig) {
					continue;
				}
				if (bestId == null || existing.getId() < bestId) {
					bestId = existing.getId();
				}
			}
			catch (Exception ignore) {}
		}
		return bestId;
	}
	
	public boolean isDuplicate(int id, String endpoint) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getEndpoint().equals(endpoint) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Checks if there is an earlier request with the same Method+Host+Path (ignoring query string).
	 */
	public boolean isDuplicateByEndpointNoQuery(int id, String method, String host, String url) {
		String targetKey = buildEndpointKeyNoQuery(method, host, url);
		for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
			String currentKey = buildEndpointKeyNoQuery(requestResponse.getMethod(), requestResponse.getHost(), requestResponse.getUrl());
			if (currentKey.equals(targetKey) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Checks if there is an earlier request with the same Method+Host+FullUrl (including query string).
	 */
	public boolean isDuplicateByFullUrl(int id, String method, String host, String fullUrl) {
		String targetKey = (method == null ? "" : method) + (host == null ? "" : host) + (fullUrl == null ? "" : fullUrl);
		for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
			String currentFullUrl = requestResponse.getFullUrl();
			String currentKey = requestResponse.getMethod() + requestResponse.getHost() + (currentFullUrl == null ? "" : currentFullUrl);
			if (currentKey.equals(targetKey) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Duplicate check that also considers request body for non-GET methods.
	 * For GET/HEAD, falls back to full URL only. For others, uses full URL + SHA-256 of request bytes.
	 */
	public boolean isDuplicateByRequestSignature(int id, String method, String host, String fullUrl, byte[] requestBytes) {
		// Use helper to compute normalized multi-dim signature
		String targetKey;
		// Build a lightweight ORR-like signature for target using method, host, URL and raw request if available
		String pathPlusQuery = (fullUrl == null) ? "" : fullUrl.substring(fullUrl.indexOf(host) + host.length());
		String pseudoUrl = pathPlusQuery;
		OriginalRequestResponseSignatureProxy proxy = new OriginalRequestResponseSignatureProxy(id, method, host, pseudoUrl, requestBytes);
		targetKey = RequestSignatureHelper.computeMultiDimSignature(proxy);
		if (mutedSignatures.contains(targetKey)) {
			return true;
		}
		for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
			String currentKey = RequestSignatureHelper.computeMultiDimSignature(requestResponse);
			if (currentKey.equals(targetKey) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}

	// Minimal proxy to reuse signature helper without changing entities
	private static class OriginalRequestResponseSignatureProxy extends OriginalRequestResponse {
		public OriginalRequestResponseSignatureProxy(int id, String method, String host, String url, byte[] requestBytes) {
			super(id, new burp.IHttpRequestResponse() {
				@Override public byte[] getRequest() { return requestBytes; }
				@Override public void setRequest(byte[] message) {}
				@Override public byte[] getResponse() { return null; }
				@Override public void setResponse(byte[] message) {}
				@Override public String getComment() { return null; }
				@Override public void setComment(String comment) {}
				@Override public String getHighlight() { return null; }
				@Override public void setHighlight(String color) {}
				@Override public burp.IHttpService getHttpService() { return new burp.IHttpService() {
					@Override public String getHost() { return host; }
					@Override public int getPort() { return 0; }
					@Override public String getProtocol() { return ""; }
				}; }
				@Override public void setHttpService(burp.IHttpService httpService) {}
			}, method, url, "", 0, 0);
		}
	}

	private String buildEndpointKeyNoQuery(String method, String host, String url) {
		String pathOnly = url;
		int q = url == null ? -1 : url.indexOf('?');
		if (q >= 0) {
			pathOnly = url.substring(0, q);
		}
		// Normalize trailing slash: treat "/path" and "/path/" as the same
		if (pathOnly != null && pathOnly.length() > 1 && pathOnly.endsWith("/")) {
			pathOnly = pathOnly.substring(0, pathOnly.length() - 1);
		}
		return (method == null ? "" : method) + (host == null ? "" : host) + (pathOnly == null ? "" : pathOnly);
	}
	
	public void deleteRequestResponse(OriginalRequestResponse requestResponse) {
		try {
			String sig = RequestSignatureHelper.computeMultiDimSignature(requestResponse);
			if (sig != null && sig.length() > 0) {
				mutedSignatures.add(sig);
			}
		}
		catch (Exception ignore) {}
		originalRequestResponseList.remove(requestResponse);
		SwingUtilities.invokeLater(new Runnable() {			
			@Override
			public void run() {
				fireTableDataChanged();
			}
		});
	}
	
	public void clearRequestMap() {
		originalRequestResponseList.clear();
		mutedSignatures.clear();
		fireTableDataChanged();
	}
	
	public OriginalRequestResponse getOriginalRequestResponse(int listIndex) {
		if(listIndex < originalRequestResponseList.size()) {
			return originalRequestResponseList.get(listIndex);
		}
		else {
			return null;
		}
	}
	
	public OriginalRequestResponse getOriginalRequestResponseById(int id) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getId() == id) {
				return requestResponse;
			}
		}
		return null;
	}
	
	@Override
	public int getColumnCount() {
		return STATIC_COLUMN_COUNT + (config.getSessions().size()*4);
	}

	@Override
	public int getRowCount() {
		return originalRequestResponseList.size();
	}

	@Override
	public Object getValueAt(int row, int column) {
		if(row >= originalRequestResponseList.size()) {
			return null;
		}
		OriginalRequestResponse originalRequestResponse = originalRequestResponseList.get(row);
		int tempColunmIndex = 5;
		if(column == 0) {
			return originalRequestResponse.getId();
		}
		if(column == 1) {
			return  originalRequestResponse.getMethod();
		}
		if(column == 2) {
			return originalRequestResponse.getHost();
		}
		if(column == 3) {
			return originalRequestResponse.getUrl();
		}
		if(column == 4) {
			return originalRequestResponse.getFullUrl();
		}
		if(column == 5) {
			return originalRequestResponse.getStatusCode();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getStatusCode();
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getResponseContentLength();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getResponseContentLength();
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				int lengthDiff = originalRequestResponse.getResponseContentLength() - 
				config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getResponseContentLength();
				return lengthDiff;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getStatus();
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getComment();
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public String getColumnName(int column) {
		int tempColunmIndex = 5;
		if(column == 0) {
			return Column.ID.toString();
		}
		if(column == 1) {
			return  Column.Method.toString();
		}
		if(column == 2) {
			return Column.Host.toString();
		}
		if(column == 3) {
			return Column.Path.toString();
		}
		if(column == 4) {
			return Column.FullUrl.toString();
		}
		if(column == 5) {
			return Column.Code.toString();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Code;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return Column.Length.toString();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Length;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Diff;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Status;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return Column.Comment.toString();
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		int tempColunmIndex = 5;
		if(columnIndex == 0) {
			return Integer.class;
		}
		if(columnIndex == 1) {
			return String.class;
		}
		if(columnIndex == 2) {
			return String.class;
		}
		if(columnIndex == 3) {
			return String.class;
		}
		if(columnIndex == 4) {
			return String.class;
		}
		if(columnIndex == 5) {
			return Integer.class;
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) {
			return Integer.class;
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return BypassConstants.class;
			}
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) {
			return String.class;
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + columnIndex);
	}
	
	public enum Column {
		ID("ID"), Method("方法"), Host("主机"), Path("路径"), FullUrl("完整URL"), Code("状态码"), Length("长度"), Diff("差异"), Status("状态"), Comment("评论");
		
		private final String displayName;
		
		Column(String displayName) {
			this.displayName = displayName;
		}
		
		@Override
		public String toString() {
			return displayName;
		}
		
		public static EnumSet<Column> getDefaultSet() {
			return EnumSet.of(ID, Method, Host, Path, FullUrl, Status);
		}
		
	}
}
