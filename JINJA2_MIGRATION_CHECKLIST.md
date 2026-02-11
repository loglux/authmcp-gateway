# Jinja2 Migration Testing Checklist

## Preparation

- [ ] Docker container running: `docker compose up -d --build`
- [ ] Check logs for errors: `docker compose logs -f fastmcp-auth`
- [ ] Login to admin panel: http://localhost:9105/admin

---

## Page 1: Dashboard (`/admin`)

### Visual Check
- [ ] Page loads without errors
- [ ] Sidebar displays correctly with all 6 menu items
- [ ] Active page indicator shows "Dashboard" as active
- [ ] Stats cards (4 cards) display correctly
- [ ] System information table displays

### Functionality
- [ ] Stats load automatically on page load
- [ ] Numbers appear in stat cards (Total Users, Active Users, Superusers, Recent Logins)
- [ ] System info populated (JWT Algorithm, Access Token TTL, etc.)
- [ ] Auto-refresh works (wait 30 seconds, check if stats update)

### Navigation
- [ ] Click "Users" in sidebar → navigates to Users page
- [ ] Browser back button works
- [ ] All sidebar links are clickable

---

## Page 2: Users (`/admin/users`)

### Visual Check
- [ ] Page loads without errors
- [ ] Sidebar shows "Users" as active
- [ ] Users table displays with correct headers
- [ ] Table shows all users with badges (Active/Inactive, Yes/No for Superuser)

### Functionality
- [ ] Users list loads automatically
- [ ] User data displays correctly (username, email, dates, status)
- [ ] Toggle status button appears for each user
- [ ] "Make Superuser" button appears only for non-superusers
- [ ] Click toggle status button → confirmation dialog appears
- [ ] Confirm status change → user status updates in table
- [ ] Click "Make Superuser" → confirmation → user becomes superuser

### Edge Cases
- [ ] Empty state (if no users) shows appropriate message
- [ ] Long usernames don't break layout
- [ ] Dates format correctly

---

## Page 3: MCP Servers (`/admin/mcp-servers`)

### Visual Check
- [ ] Page loads without errors
- [ ] Sidebar shows "MCP Servers" as active
- [ ] "Add Server" button visible
- [ ] Server cards display (if servers exist)
- [ ] Status badges show correctly (Online/Error/Unknown)

### Functionality
- [ ] Servers list loads automatically
- [ ] Click "Add Server" → modal opens
- [ ] Fill in server details in modal:
  - [ ] Name field works
  - [ ] URL field works
  - [ ] Description field works
  - [ ] Tool Prefix field works
  - [ ] Auth Type dropdown works
  - [ ] Auth token field shows/hides based on auth type
  - [ ] Enabled checkbox works
- [ ] Click "Add Server" (in modal) → server added to list
- [ ] Click "Test" on server card → test runs, result shows
- [ ] Click "Tools" on server card → tools list appears
- [ ] Click "Delete" on server card → confirmation → server deleted

### Edge Cases
- [ ] Empty state shows "No MCP servers configured" message
- [ ] Modal closes properly (X button, Cancel button, backdrop click)
- [ ] Form validation works (required fields)

---

## Page 4: Settings (`/admin/settings`)

### Visual Check
- [ ] Page loads without errors
- [ ] Sidebar shows "Settings" as active
- [ ] Three settings sections display:
  - [ ] JWT Configuration
  - [ ] Password Policy
  - [ ] System Settings
- [ ] All form fields visible
- [ ] "Save All Settings" button visible

### Functionality
- [ ] Settings load automatically on page load
- [ ] JWT settings populated:
  - [ ] Access Token TTL shows current value
  - [ ] Refresh Token TTL shows current value
- [ ] Password policy settings populated:
  - [ ] Minimum Length shows value
  - [ ] All checkboxes reflect current state
- [ ] System settings populated:
  - [ ] Allow Registration checkbox state
  - [ ] Auth Required checkbox state
- [ ] Change a value (e.g., Access Token TTL)
- [ ] Click "Save All Settings" → success message appears
- [ ] Refresh page → changed value persists
- [ ] Click "Reset" button → values reload from server

### Edge Cases
- [ ] Number inputs enforce min/max values
- [ ] Success alert auto-disappears after 3 seconds
- [ ] Error handling works (try invalid value if possible)

---

## Page 5: Logs (`/admin/logs`)

### Visual Check
- [ ] Page loads without errors
- [ ] Sidebar shows "Logs" as active
- [ ] Filter dropdowns visible (Event Type, Limit)
- [ ] "Refresh" button visible
- [ ] Logs container displays

### Functionality
- [ ] Logs load automatically on page load
- [ ] Log entries display with:
  - [ ] Event type badge (color-coded)
  - [ ] Username
  - [ ] Success/failure icon
  - [ ] Timestamp (formatted)
  - [ ] IP address (if available)
  - [ ] Details (if available)
- [ ] Border color matches status (green=success, red=failed)
- [ ] Filter by event type:
  - [ ] Select "Login" → only login events show
  - [ ] Select "Failed Login" → only failed logins show
  - [ ] Select "All Events" → all events show
- [ ] Change limit:
  - [ ] Select "Last 50" → max 50 entries
  - [ ] Select "Last 100" → max 100 entries
- [ ] Click "Refresh" → logs reload
- [ ] Auto-refresh works (wait 30 seconds, check if logs update)

### Edge Cases
- [ ] Empty state shows "No logs found" message
- [ ] Long details don't break layout
- [ ] Hover effect on log entries works

---

## Page 6: API Test (`/admin/api-test`)

### Visual Check
- [ ] Page loads without errors
- [ ] Sidebar shows "API Test" as active
- [ ] Four test cards display:
  - [ ] POST /auth/register (blue)
  - [ ] POST /oauth/token (green)
  - [ ] GET /auth/me (cyan)
  - [ ] POST /mcp (yellow)
- [ ] All input fields visible
- [ ] All "Test" buttons visible

### Functionality - Register Test
- [ ] Default values populated (testuser, test@example.com)
- [ ] Enter unique username and email
- [ ] Enter password (e.g., Test123!@#)
- [ ] Click "Test" → response appears in pre block
- [ ] Response shows user object with id, username, email
- [ ] Status code visible (200 or 400 if user exists)

### Functionality - Login Test
- [ ] Enter username from previous test
- [ ] Enter password
- [ ] Click "Test" → response appears
- [ ] Response contains access_token and refresh_token
- [ ] Tokens auto-filled into "Get Me" and "MCP" fields

### Functionality - Get Me Test
- [ ] Token field auto-filled from login
- [ ] Click "Test" → response appears
- [ ] Response shows user profile data
- [ ] Try with invalid token → error message

### Functionality - MCP Test
- [ ] Token field auto-filled from login
- [ ] Click "Test" → response appears
- [ ] Response shows MCP protocol response (list of knowledge bases)
- [ ] Try with invalid token → error message

### Edge Cases
- [ ] Response blocks expand correctly
- [ ] JSON formatting in responses is readable
- [ ] Scroll works if response is long
- [ ] Error messages display clearly

---

## Cross-Page Testing

### Navigation Flow
- [ ] Dashboard → Users → MCP Servers → Settings → Logs → API Test → Dashboard
- [ ] All transitions smooth, no broken links
- [ ] Active page indicator updates correctly
- [ ] Browser back/forward buttons work
- [ ] Direct URL access works for each page

### Responsive Design
- [ ] Test on narrow window (simulate mobile)
- [ ] Sidebar behavior on small screens
- [ ] Cards stack correctly on mobile
- [ ] Forms remain usable on small screens

### Performance
- [ ] All pages load in < 2 seconds
- [ ] No console errors in browser DevTools (F12)
- [ ] No 404 errors for assets (CSS, JS, icons)
- [ ] Auto-refresh doesn't cause memory leaks (check after 5 minutes)

---

## Browser Compatibility (Optional)

- [ ] Chrome/Edge - all features work
- [ ] Firefox - all features work
- [ ] Safari - all features work (if available)

---

## Final Checks

- [ ] All 6 pages tested and working
- [ ] No JavaScript errors in console
- [ ] No Python errors in Docker logs
- [ ] All CRUD operations work
- [ ] All filters/searches work
- [ ] All modals work
- [ ] All forms validate correctly
- [ ] All API integrations work

---

## Post-Testing Actions

After all checks pass:

1. **Document issues** (if any found)
   - Create list of bugs to fix
   - Note any visual inconsistencies
   - Report any performance issues

2. **Remove old functions** (if all tests pass)
   - Delete all `*_OLD()` functions from `src/fastmcp_auth/admin/routes.py`
   - Git commit with message: "Remove old inline HTML functions after successful Jinja2 migration"

3. **Cleanup** (if all tests pass)
   - Remove this checklist file (or move to docs/)
   - Update MEMORY.md with lessons learned

---

## Test Results Summary

**Tester**: _________________
**Date**: _________________
**Total Checks**: 100+
**Passed**: ___ / ___
**Failed**: ___ / ___
**Notes**:

```
[Space for notes]
```

---

## Quick Test Script (for repeated testing)

```bash
# Start container
docker compose up -d --build

# Wait for startup
sleep 5

# Open admin panel
open http://localhost:9105/admin  # macOS
# or
xdg-open http://localhost:9105/admin  # Linux
# or manually open in browser

# Watch logs
docker compose logs -f fastmcp-auth
```
