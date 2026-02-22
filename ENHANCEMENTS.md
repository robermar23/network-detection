# ENHANCEMENTS

-- Add --

1. Add options for filtering the scan results for every view.  The OS, Vendor, and IP address should be filterable by "contains" and "equals".
2. Add options for sorting the scan results for every view.  The OS, Vendor, and IP address should be sortable.
3. Optimize the header for the main application dashboard.  With filtering and sorting, the header should be optimized to show the number of results that match the filter and sort criteria.  We need room to fit the new options.
4. Add a "deep scan all" button to the main application dashboard.  This button should trigger a deep scan for all hosts in the scan results.  Overall progress needs to be known as well as an option to cancel the deep scan.

-- Fix --

1. The deep scan results should be saved with the rest of the scan results and also loaded with the rest of the scan results.  When show details is clicked, it should recognized that the deep scan results are already loaded and display those results.  The button should cahnge to "re-run deep scan".  The deep scan results should be cleared when the scan is cleared.
2. when the user is provided the option to open an ssh session on their host to the target, the user should be able to enter the username to use to connect to the target.
