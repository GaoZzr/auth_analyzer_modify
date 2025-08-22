package burp;

import java.awt.Component;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.AuthAnalyzerMenu;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.Globals;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

	public static MainPanel mainPanel;
	private JMenu authAnalyzerMenu = null;
	public static IBurpExtenderCallbacks callbacks;
	public static JTabbedPane burpTabbedPane = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		callbacks.setExtensionName(Globals.EXTENSION_NAME);
		mainPanel = new MainPanel();
		callbacks.addSuiteTab(this);
		addAuthAnalyzerMenu();
		HttpListener httpListener = new HttpListener();
		callbacks.registerHttpListener(httpListener);
		callbacks.registerProxyListener(httpListener);
		callbacks.registerExtensionStateListener(this);
		callbacks.printOutput(Globals.EXTENSION_NAME + " 修改版");
		callbacks.printOutput("基于版本修改 " + Globals.VERSION);

	}

	@Override
	public String getTabCaption() {
		return Globals.EXTENSION_NAME;
	}

	@Override
	public Component getUiComponent() {
		// 添加组件可见性监听器来修复UI渲染问题
		mainPanel.addComponentListener(new ComponentListener() {
			@Override
			public void componentShown(ComponentEvent e) {
				// 当标签页重新显示时，强制刷新UI
				SwingUtilities.invokeLater(() -> {
					// 使用MainPanel的专用刷新方法
					mainPanel.forceRefreshUI();
					// 额外延迟刷新，确保所有组件都已完全显示
					SwingUtilities.invokeLater(() -> {
						mainPanel.forceRefreshUI();
					});
				});
			}

			@Override
			public void componentHidden(ComponentEvent e) {
				// 标签页隐藏时的处理（如果需要）
			}

			@Override
			public void componentMoved(ComponentEvent e) {
				// 组件移动时的处理
			}

			@Override
			public void componentResized(ComponentEvent e) {
				// 组件大小改变时的处理
			}
		});
		return mainPanel;
	}
	
	/**
	 * 递归刷新所有子组件
	 */
	private void refreshAllComponents(Component component) {
		if (component == null) return;
		
		// 刷新当前组件
		component.revalidate();
		component.repaint();
		
		// 如果是容器，递归刷新子组件
		if (component instanceof java.awt.Container) {
			java.awt.Container container = (java.awt.Container) component;
			for (Component child : container.getComponents()) {
				refreshAllComponents(child);
			}
		}
	}
	
	private void addAuthAnalyzerMenu() {
		SwingUtilities.invokeLater(new Runnable() {
			
			@Override
			public void run() {
				JFrame burpFrame = GenericHelper.getBurpFrame();
				if(burpFrame != null) {
					authAnalyzerMenu = new AuthAnalyzerMenu(Globals.EXTENSION_NAME);
					JMenuBar burpMenuBar = burpFrame.getJMenuBar();
					burpMenuBar.add(authAnalyzerMenu, burpMenuBar.getMenuCount() - 1);
				}
			}
		});

	}

	@Override
	public void extensionUnloaded() {
		if(authAnalyzerMenu != null && authAnalyzerMenu.getParent() != null) {
			authAnalyzerMenu.getParent().remove(authAnalyzerMenu);
		}
		try {
			mainPanel.getConfigurationPanel().createSessionObjects(false);
			DataStorageProvider.saveSetup();
		}
		catch (Exception e) {
			callbacks.printOutput("INFO: Session Setup not stored due to invalid data.");
		}
	}
}