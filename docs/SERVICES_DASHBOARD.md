# Services Dashboard

The Arqut Server includes a built-in web dashboard for viewing and monitoring registered edge services.

## Features

- **Real-time Service Monitoring**: View all registered edge services in a sleek, modern interface
- **Advanced Filtering**:
  - Filter by Edge ID
  - Search by service name
  - Filter by enabled/disabled status
- **Statistics Overview**: See total services, active edges, enabled services, and filtered results at a glance
- **Light/Dark Theme**: Toggle between light and dark themes with persistent preference
- **Auto-refresh**: Dashboard automatically refreshes every 30 seconds
- **Responsive Design**: Works perfectly on desktop, tablet, and mobile devices

## Accessing the Dashboard

The dashboard HTML page is publicly accessible at:

```
http://localhost:9000/dashboard/services
```

Or if you're running on a remote server:

```
http://your-server-domain:9000/dashboard/services
```

### API Key Configuration

**Important**: You need to configure your API key to view service data:

1. Open the dashboard in your browser
2. Locate the "🔑 API Key Configuration" section at the top
3. Enter your API key (starts with `arq_`)
4. Click "Save Key"

Your API key is stored securely in your browser's localStorage and is used to authenticate requests to the services API.

To get your API key:

```bash
# Generate a new API key (if you don't have one)
./arqut-server apikey generate -c config.yaml

# Check status of existing key
./arqut-server apikey status -c config.yaml
```

## Dashboard Interface

### Statistics Cards

At the top of the dashboard, you'll see four statistics cards:

- **Total Services**: Total number of registered services across all edges
- **Active Edges**: Number of unique edge instances with registered services
- **Enabled Services**: Count of services that are currently enabled
- **Filtered Results**: Number of services matching your current filters

### Filters

Use the filter controls to narrow down the service list:

- **Filter by Edge ID**: Select a specific edge from the dropdown
- **Search Service Name**: Type to search service names in real-time
- **Filter by Status**: Show only enabled or disabled services

### Service Cards

Each service is displayed in a card showing:

- Edge ID badge
- Service name and ID
- Status (enabled/disabled)
- Protocol (TCP/UDP)
- Tunnel port
- Local host and port
- Created and updated timestamps

### Theme Toggle

Click the theme toggle button in the top-right corner to switch between light and dark modes. Your preference is saved in browser localStorage.

## API Endpoint

The dashboard fetches data from the protected API endpoint:

```
GET /api/v1/services
Authorization: Bearer <api-key>
```

**Note**: The dashboard HTML page itself is public, but the data API endpoint requires authentication. When you save your API key in the dashboard, it's stored in your browser's localStorage and automatically included in all API requests.

## Technical Details

- **Technology**: Pure HTML, CSS, and vanilla JavaScript (no framework dependencies)
- **Embedded**: The HTML is embedded in the Go binary using `go:embed`
- **Auto-refresh**: Data refreshes every 30 seconds automatically
- **Responsive**: Mobile-first design with CSS Grid

## Example Service Data

Services are displayed with the following information:

```json
{
  "id": "svc-abc123",
  "edge_id": "edge-prod-01",
  "name": "Web Server",
  "tunnel_port": 8080,
  "local_host": "localhost",
  "local_port": 3000,
  "protocol": "tcp",
  "enabled": true,
  "created_at": "2025-10-19T20:00:00Z",
  "updated_at": "2025-10-19T20:00:00Z"
}
```

## Browser Compatibility

The dashboard works in all modern browsers:

- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)
- Opera (latest)

## Security Note

While the dashboard HTML page is publicly accessible, the actual service data is fetched from an authenticated API endpoint. This means:

- Anyone can view the dashboard interface
- Only requests with valid API keys can retrieve service data
- For production deployments, consider placing the dashboard behind a reverse proxy with authentication

## Troubleshooting

### Dashboard shows "Please configure your API key"

- Click on the API key input field at the top of the dashboard
- Enter your API key (you can generate one with `./arqut-server apikey generate`)
- Click "Save Key"
- The page will automatically reload and fetch services

### Dashboard shows "Invalid API key"

- Your API key may be incorrect or expired
- Clear the current key by clicking "Clear" button
- Generate a new API key: `./arqut-server apikey rotate -c config.yaml`
- Enter the new key in the dashboard

### Dashboard shows "Failed to load services"

- Check that the API server is running on the expected port
- Verify CORS settings if accessing from a different origin
- Check browser console for detailed error messages
- Ensure your API key is valid

### Services not appearing

- Ensure edge devices have successfully synced their services via WebSocket
- Check that services are enabled in the edge configuration
- Verify your API key is configured correctly
- Use browser DevTools Network tab to verify API responses

### API key not saving

- Ensure browser allows localStorage
- Check for browser extensions that may block storage
- Try opening the dashboard in incognito/private mode to test

### Theme not persisting

- Ensure browser allows localStorage
- Check for browser extensions that may block storage
- Try clearing browser cache and reload
