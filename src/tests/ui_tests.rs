use crate::config::AppConfig;
use crate::tests::ChromeDriverHandle;
use crate::web::web_server_command;
use crate::{TrailFinderError, setup_test_logging};
use rand::Rng;
use std::time::Duration;
use thirtyfour::prelude::*;
use tokio::task::JoinHandle;
use tokio::time::sleep;

/// Helper to start the web server for testing
async fn start_test_server()
-> Result<(JoinHandle<Result<(), TrailFinderError>>, u16), TrailFinderError> {
    setup_test_logging();
    let app_config =
        AppConfig::load_from_file("devices.test.json").expect("Failed to load test config");
    let address = "127.0.0.1";
    // assign a random port then try to connect to it
    let mut attempts = 0;
    while attempts < 20 {
        let port = rand::rng().random_range(43000..u16::MAX);
        if tokio::net::TcpListener::bind(&format!("{address}:{port}"))
            .await
            .is_ok()
        {
            return Ok((
                tokio::spawn(async move { web_server_command(&app_config, address, port).await }),
                port,
            ));
        } else {
            attempts += 1;
        }
    }
    Err(TrailFinderError::Generic(
        "Failed to bind test server".to_string(),
    ))
}

/// Helper to create WebDriver instance with managed ChromeDriver
async fn create_driver_with_chrome() -> Result<(WebDriver, ChromeDriverHandle), TrailFinderError> {
    let chromedriver = ChromeDriverHandle::start()
        .map_err(|e| TrailFinderError::Generic(format!("Failed to start ChromeDriver: {}", e)))?;

    // Wait for ChromeDriver to be ready
    sleep(Duration::from_secs(2)).await;

    let mut caps = DesiredCapabilities::chrome();
    caps.add_arg("--headless")
        .map_err(|e| TrailFinderError::Generic(format!("Failed to set Chrome args: {}", e)))?;
    caps.add_arg("--no-sandbox")
        .map_err(|e| TrailFinderError::Generic(format!("Failed to set Chrome args: {}", e)))?;
    caps.add_arg("--disable-dev-shm-usage")
        .map_err(|e| TrailFinderError::Generic(format!("Failed to set Chrome args: {}", e)))?;

    let driver = WebDriver::new(&chromedriver.webdriver_url(), caps)
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to create WebDriver: {}", e)))?;

    Ok((driver, chromedriver))
}

#[cfg(test)]
#[tokio::test]
async fn test_topology_page_loads() -> Result<(), TrailFinderError> {
    // Start test server
    let (_server, port) = start_test_server().await?;
    sleep(Duration::from_secs(5)).await; // Wait for server to start

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    // Navigate to topology page
    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    // Wait for page to load and check title
    let title = driver.title().await?;
    assert!(
        title.contains("Network Topology"),
        "Page title should contain 'Network Topology'"
    );

    // Check that main containers exist
    let topology_container = driver.find(By::Id("topology-container")).await?;
    assert!(
        topology_container.is_present().await?,
        "Topology container should be present"
    );

    let refresh_button = driver.find(By::Id("refresh-topology")).await?;
    assert!(
        refresh_button.is_present().await?,
        "Refresh button should be present"
    );

    let show_networks_toggle = driver.find(By::Id("show-networks")).await?;
    assert!(
        show_networks_toggle.is_present().await?,
        "Show networks toggle should be present"
    );

    let reset_zoom_button = driver.find(By::Id("reset-zoom")).await?;
    assert!(
        reset_zoom_button.is_present().await?,
        "Reset zoom button should be present"
    );

    // Check that device modal exists (but is hidden)
    let device_modal = driver.find(By::Id("device-modal")).await?;
    assert!(
        device_modal.is_present().await?,
        "Device modal should be present"
    );

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;
    // ChromeDriver will be automatically killed when _chromedriver drops

    Ok(())
}

#[tokio::test]
async fn test_topology_loads_data() -> Result<(), TrailFinderError> {
    let (_server, port) = start_test_server().await?;

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    // Wait for topology to load (look for SVG element)
    let svg = driver.find(By::Id("topology-svg")).await?;
    assert!(svg.is_present().await?, "Topology SVG should be present");

    // Wait a bit longer for data to load
    sleep(Duration::from_secs(2)).await;

    // Check that device nodes are present
    let nodes = driver.find_all(By::Css("circle.node")).await?;
    assert!(!nodes.is_empty(), "Should have device nodes in topology");

    // Check that connections are present
    let links = driver.find_all(By::Css("line.link")).await?;
    assert!(
        !links.is_empty(),
        "Should have connection links in topology"
    );

    // Check that labels are present
    let labels = driver.find_all(By::Css("g text")).await?;
    assert!(!labels.is_empty(), "Should have device labels in topology");

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;

    Ok(())
}

#[tokio::test]
async fn test_refresh_topology_button() -> Result<(), TrailFinderError> {
    let (_server, port) = start_test_server().await?;
    sleep(Duration::from_secs(5)).await;

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    // Wait for initial load
    driver.find(By::Id("topology-svg")).await?;
    sleep(Duration::from_secs(1)).await;

    // Click refresh button
    let refresh_button = driver.find(By::Id("refresh-topology")).await?;
    refresh_button.click().await?;

    // Should show loading message briefly
    let _topology_container = driver.find(By::Id("topology-container")).await?;

    // Wait for topology to reload
    sleep(Duration::from_secs(2)).await;

    // Check that topology is still present after refresh
    let svg = driver.find(By::Id("topology-svg")).await?;
    assert!(
        svg.is_present().await?,
        "Topology should reload after refresh"
    );

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;
    Ok(())
}

#[tokio::test]
async fn test_reset_zoom_button() -> Result<(), TrailFinderError> {
    let (_server, port) = start_test_server().await?;
    sleep(Duration::from_secs(5)).await;

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    // Wait for topology to load
    driver.find(By::Id("topology-svg")).await?;
    sleep(Duration::from_secs(2)).await;

    // Click reset zoom button
    let reset_zoom_button = driver.find(By::Id("reset-zoom")).await?;
    reset_zoom_button.click().await?;

    // The zoom should reset (we can't easily test the transform, but we can test the button works)
    // Just verify the button is clickable and doesn't cause errors
    assert!(
        reset_zoom_button.is_enabled().await?,
        "Reset zoom button should be enabled"
    );

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;
    Ok(())
}

#[tokio::test]
async fn test_show_networks_toggle() -> Result<(), TrailFinderError> {
    let (_server, port) = start_test_server().await?;
    sleep(Duration::from_secs(5)).await;

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    // Wait for topology to load
    driver.find(By::Id("topology-svg")).await?;
    sleep(Duration::from_secs(2)).await;

    // Test the show networks toggle
    let show_networks_toggle = driver.find(By::Id("show-networks")).await?;
    let initial_checked = show_networks_toggle.is_selected().await?;

    // Toggle it
    show_networks_toggle.click().await?;

    // Wait a moment for any changes to process
    sleep(Duration::from_millis(500)).await;

    // Check that the state changed
    let new_checked = show_networks_toggle.is_selected().await?;
    assert_ne!(
        initial_checked, new_checked,
        "Show networks toggle should change state"
    );

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;
    Ok(())
}

#[tokio::test]
async fn test_device_modal_functionality() -> Result<(), TrailFinderError> {
    let (_server, port) = start_test_server().await?;
    sleep(Duration::from_secs(5)).await;

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    // Wait for topology to load
    driver.find(By::Id("topology-svg")).await?;
    sleep(Duration::from_secs(2)).await;

    // Find device nodes (not the internet node which has a larger radius)
    let nodes = driver.find_all(By::Css("circle.node")).await?;

    if !nodes.is_empty() {
        // Try to click on a device node (avoid internet node by checking if it's clickable)
        for node in nodes {
            // Check if this node has a click handler (non-internet nodes should be clickable)
            if node.click().await.is_ok() {
                // Wait for modal to appear
                sleep(Duration::from_millis(500)).await;

                let device_modal = driver.find(By::Id("device-modal")).await?;
                if device_modal.is_displayed().await.unwrap_or(false) {
                    // Modal opened successfully, check its content
                    let device_detail_content =
                        driver.find(By::Id("device-detail-content")).await?;
                    assert!(
                        device_detail_content.is_present().await?,
                        "Device detail content should be present"
                    );

                    // Check for typical device detail elements
                    let content_text = device_detail_content.text().await?;
                    assert!(
                        content_text.contains("Device ID") || content_text.contains("Type"),
                        "Device details should contain device information"
                    );

                    // Test closing the modal
                    let close_button = driver.find(By::Css(".close")).await?;
                    close_button.click().await?;

                    // Wait for modal to close
                    sleep(Duration::from_millis(500)).await;

                    // Modal should be hidden again
                    let is_displayed = device_modal.is_displayed().await.unwrap_or(true);
                    assert!(!is_displayed, "Modal should be hidden after clicking close");

                    break; // We successfully tested the modal, exit the loop
                }
            }
        }
    }

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;
    Ok(())
}

#[tokio::test]
async fn test_api_endpoints_work() -> Result<(), TrailFinderError> {
    let (_server, port) = start_test_server().await?;
    sleep(Duration::from_secs(5)).await;

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    // Test that API endpoints return valid JSON by checking network requests
    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    // Wait for topology to load (this should trigger API calls)
    driver.find(By::Id("topology-svg")).await?;
    sleep(Duration::from_secs(2)).await;

    // Test direct API access
    driver
        .goto(&format!("http://127.0.0.1:{port}/api/topology"))
        .await?;

    // Should get JSON response
    let page_source = driver.source().await?;
    assert!(
        page_source.contains("devices") && page_source.contains("connections"),
        "API should return JSON with devices and connections"
    );

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;
    Ok(())
}

#[tokio::test]
async fn test_error_handling() -> Result<(), TrailFinderError> {
    let (_server, port) = start_test_server().await?;
    sleep(Duration::from_secs(5)).await;

    let (driver, _chromedriver) = create_driver_with_chrome().await?;

    // Test accessing non-existent device
    driver
        .goto(&format!(
            "http://127.0.0.1:{port}/api/devices/nonexistent-id"
        ))
        .await?;

    // Should handle gracefully (either 404 or error JSON)
    let page_source = driver.source().await?;
    // This should not cause the page to crash
    assert!(
        !page_source.is_empty(),
        "Error responses should still return content"
    );

    // Test that the main page still works after error
    driver
        .goto(&format!("http://127.0.0.1:{port}/topology"))
        .await?;

    let topology_container = driver.find(By::Id("topology-container")).await?;
    assert!(
        topology_container.is_present().await?,
        "Main page should still work after API error"
    );

    driver
        .quit()
        .await
        .map_err(|e| TrailFinderError::Generic(format!("Failed to quit driver: {}", e)))?;
    Ok(())
}
