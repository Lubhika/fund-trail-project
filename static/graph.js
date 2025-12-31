// Fetching Branch data from IFSC Code. calling Razorpay IFSC API
const branchCache = new Map();
const isViewer = typeof window !== "undefined" ? Boolean(window.isViewerRole) : false;

async function fetchBranchInfo(ifsc) {
  if (!ifsc) return { BRANCH: 'Unknown' };
  if (branchCache.has(ifsc)) {
    return { BRANCH: branchCache.get(ifsc) };
  }
  try {
    const res = await fetch(`https://ifsc.razorpay.com/${ifsc}`);
    if (!res.ok) throw new Error("Invalid IFSC");
    const data = await res.json();
    const branch = data?.BRANCH || 'Unknown';
    branchCache.set(ifsc, branch);
    return { BRANCH: branch };
  } catch (e) {
    console.error("Failed to fetch IFSC details:", e);
    branchCache.set(ifsc, 'Unknown');
    return { BRANCH: 'Unknown' };
  } //to catch any errors that happen during the API call
}

async function populateBranchNames(root) {
  if (!root || !root.descendants) return;
  const nodesWithIfsc = root.descendants().filter(n => n?.data?.ifsc);
  if (nodesWithIfsc.length === 0) return;
  const uniqueIfsc = [...new Set(nodesWithIfsc.map(n => n.data.ifsc))];
  await Promise.all(uniqueIfsc.map(ifsc => fetchBranchInfo(ifsc)));
  nodesWithIfsc.forEach(n => {
    const cachedBranch = branchCache.get(n.data.ifsc);
    n.data.branch = cachedBranch || 'Unknown';
  });
}

// Setting layerwise colours of node
const layerColors = {
  1: '#A7F3D0', 2: '#F97316', 3: '#f8f7f5ff',
  4: '#f8f7f5ff', 5: '#f8f7f5ff', 6: '#f8f7f5ff',
  7: '#f8f7f5ff', 8: '#f8f7f5ff', 9: '#f8f7f5ff', 10: '#17b350ff'
};;

const tooltip = d3.select('.tooltip');
const detailsPanel = document.getElementById('detailsPanel');
const detailsContent = document.getElementById('detailsContent');
const closeBtn = document.getElementById('closeDetails');
closeBtn.onclick = () => detailsPanel.style.display = 'none';

const leftPanel = document.getElementById('leftPanel');
const leftContent = document.getElementById('leftContent');
const closeLeft = document.getElementById('closeLeftPanel');
closeLeft.onclick = () => leftPanel.style.display = 'none';

// Put on hold modal elements
const holdModalOverlay = document.getElementById('holdModalOverlay');
const holdTableBody = document.getElementById('holdTableBody');
const holdStatusText = document.getElementById('holdStatusText');
const closeHoldModalBtn = document.getElementById('closeHoldModal');
const holdFilterMenu = document.getElementById('holdFilterMenu');

// Hold table filter state
let holdRowsData = [];
let holdFilters = {};
let holdSort = { column: null, direction: null };
let currentHoldFilterColumn = null;
let holdFilterDocHandler = null;

if (closeHoldModalBtn) {
  closeHoldModalBtn.onclick = closeHoldModal;
}
if (holdModalOverlay) {
  holdModalOverlay.addEventListener('click', (e) => {
    if (e.target === holdModalOverlay) closeHoldModal();
  });
}

let width, height, svg, g, currentRoot = null;
let isFirstDraw = true;
let expandAllActive = false;
svg = d3.select('#treeSvg');
g = svg.append('g').attr('transform', 'translate(80,80)');
svg.call(d3.zoom().scaleExtent([0.5, 3]).on('zoom', e => g.attr('transform', e.transform)));

async function openHoldPopup() {
  if (!holdModalOverlay) return;
  holdModalOverlay.style.display = 'flex';
  if (holdStatusText) holdStatusText.textContent = 'Loading...';
  if (holdTableBody) holdTableBody.innerHTML = '';
  holdFilters = {};
  holdSort = { column: null, direction: null };
  currentHoldFilterColumn = null;
  if (holdFilterMenu) holdFilterMenu.style.display = 'none';

  try {
    const res = await fetch(`/put_on_hold_transactions/${ackNo}`);
    if (!res.ok) throw new Error('Failed to fetch hold transactions');
    const data = await res.json();

    // Enrich rows with branch names derived from IFSC (cached per IFSC)
    const rowsWithBranch = await Promise.all(
      (data || []).map(async (row) => {
        if (row?.branch_name) return row;
        const info = await fetchBranchInfo(row?.ifsc_code);
        return { ...row, branch_name: info?.BRANCH || 'Unknown' };
      })
    );

    renderHoldTable(rowsWithBranch || []);
  } catch (err) {
    console.error('Error loading hold transactions', err);
    if (holdStatusText) holdStatusText.textContent = 'Failed to load put-on-hold transactions.';
  }

  // Viewer: make hold modal read-only
  if (isViewer && holdModalOverlay) {
    holdModalOverlay.querySelectorAll('input, select, textarea').forEach(el => el.disabled = true);
    const saveBtn = holdModalOverlay.querySelector('button[type="submit"], button#saveHoldExtraBtn');
    if (saveBtn) saveBtn.style.display = 'none';
  }
}

function closeHoldModal() {
  if (holdModalOverlay) holdModalOverlay.style.display = 'none';
}

function renderHoldTable(rows) {
  if (!holdTableBody) return;
  holdRowsData = rows || [];

  if (!holdRowsData || holdRowsData.length === 0) {
    holdTableBody.innerHTML = '';
    if (holdStatusText) holdStatusText.textContent = 'No put-on-hold transactions found for this complaint.';
    return;
  }

  if (holdStatusText) holdStatusText.textContent = '';
  applyHoldFilters();

  // Attach filter button listeners
  if (holdModalOverlay) {
    holdModalOverlay.querySelectorAll('.hold-filter-btn').forEach(btn => {
      btn.onclick = (e) => {
        e.stopPropagation();
        showHoldFilterMenu(btn);
      };
    });
  }

  holdTableBody.querySelectorAll('.hold-account-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const acc = link.getAttribute('data-account-number');
      expandHoldAccount(acc);
    });
  });
}

function formatHoldValue(row, column) {
  switch (column) {
    case 'account_number':
      return row.account_number || 'N/A';
    case 'bank_name':
      return row.bank_name || 'N/A';
    case 'branch_name':
      return row.branch_name || 'N/A';
    case 'ifsc_code':
      return row.ifsc_code || 'N/A';
    case 'amount':
      return `₹${Number(row.amount ?? 0).toLocaleString('en-IN')}`;
    case 'layer':
      return row.layer != null ? String(row.layer) : 'N/A';
    default:
      return '';
  }
}

function normalizeFilterValue(column, rawValue) {
  if (rawValue === undefined || rawValue === null) return 'N/A';
  const value = String(rawValue).trim();

  if (column === 'amount') {
    const numeric = Number(value.replace(/[₹,\s]/g, ''));
    return Number.isFinite(numeric) ? numeric : 'N/A';
  }

  if (column === 'layer') {
    const numeric = Number(value.replace(/[^\d.-]/g, ''));
    return Number.isFinite(numeric) ? numeric : 'N/A';
  }

  return value;
}

function getHoldSortValue(row, column) {
  switch (column) {
    case 'amount':
      return Number(row.amount ?? 0);
    case 'layer':
      return Number(row.layer ?? 0);
    case 'account_number':
      return row.account_number || '';
    case 'bank_name':
      return row.bank_name || '';
    case 'branch_name':
      return row.branch_name || '';
    case 'ifsc_code':
      return row.ifsc_code || '';
    default:
      return '';
  }
}

function sortHoldRows(rows) {
  if (!holdSort.column || !holdSort.direction) return rows;
  const sorted = [...rows];
  sorted.sort((a, b) => {
    const aVal = getHoldSortValue(a, holdSort.column);
    const bVal = getHoldSortValue(b, holdSort.column);
    if (aVal < bVal) return holdSort.direction === 'asc' ? -1 : 1;
    if (aVal > bVal) return holdSort.direction === 'asc' ? 1 : -1;
    return 0;
  });
  return sorted;
}

function applyHoldFilters() {
  if (!holdTableBody) return;
  const filtered = holdRowsData.filter(row => {
    return Object.entries(holdFilters).every(([col, selected]) => {
      if (!selected || selected.size === 0) return true;
      const value = normalizeFilterValue(col, formatHoldValue(row, col));
      return selected.has(value);
    });
  });

  const sortedRows = sortHoldRows(filtered);

  holdTableBody.innerHTML = sortedRows.map((row, idx) => `
    <tr>
      <td><input type="checkbox" class="hold-row-select" data-account-number="${row.account_number || ''}"></td>
      <td>${idx + 1}</td>
      <td>
        <a href="#" class="hold-account-link" data-account-number="${row.account_number || ''}">
          ${row.account_number || 'N/A'}
        </a>
      </td>
      <td>${row.bank_name || 'N/A'}</td>
      <td>${row.branch_name || 'N/A'}</td>
      <td>${row.ifsc_code || 'N/A'}</td>
      <td>${formatHoldValue(row, 'amount')}</td>
      <td>${row.layer || 'N/A'}</td>
    </tr>
  `).join('');

  holdTableBody.querySelectorAll('.hold-account-link').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const acc = link.getAttribute('data-account-number');
      expandHoldAccount(acc);
    });
  });
}

function showHoldFilterMenu(button) {
  if (!holdFilterMenu) return;
  const column = button.dataset.column;
  currentHoldFilterColumn = column;

  const allValues = [...new Set(
    holdRowsData.map(row => normalizeFilterValue(column, formatHoldValue(row, column)))
  )].sort((a, b) => {
    const aNum = typeof a === 'number';
    const bNum = typeof b === 'number';
    if (aNum && bNum) return a - b;
    if (aNum) return -1;
    if (bNum) return 1;
    return String(a).localeCompare(String(b), undefined, { numeric: true });
  });

  const selected = holdFilters[column]
    ? new Set([...holdFilters[column]].map(v => normalizeFilterValue(column, v)))
    : new Set(allValues);

  const bodyHtml = allValues.map(val => `
    <label>
      <input type="checkbox" value="${String(val).replace(/"/g, '&quot;')}" ${selected.has(val) ? 'checked' : ''}>
      <span>${val}</span>
    </label>
  `).join('');

  holdFilterMenu.innerHTML = `
    <div class="menu-header">
      <span>Filter by ${button.parentElement?.textContent?.trim() || column}</span>
      <button aria-label="Close filter" style="border:none;background:none;cursor:pointer;font-size:16px;">×</button>
    </div>
    <div class="menu-sort">
      <button type="button" data-sort="asc">Ascending ↑</button>
      <button type="button" data-sort="desc">Descending ↓</button>
    </div>
    <div class="menu-actions">
      <button type="button" data-action="select-all">Select All</button>
      <button type="button" data-action="clear-all">Clear</button>
    </div>
    <div class="menu-body">${bodyHtml}</div>
    <div class="menu-footer">
      <button class="clear-btn" type="button" data-action="reset">Reset</button>
      <button class="apply-btn" type="button" data-action="apply">Apply</button>
    </div>
  `;

  const rect = button.getBoundingClientRect();
  holdFilterMenu.style.top = `${rect.bottom + window.scrollY + 4}px`;
  holdFilterMenu.style.left = `${rect.left + window.scrollX}px`;
  holdFilterMenu.style.display = 'block';
  holdFilterMenu.setAttribute('aria-hidden', 'false');

  const closeMenu = () => {
    holdFilterMenu.style.display = 'none';
    holdFilterMenu.setAttribute('aria-hidden', 'true');
    if (holdFilterDocHandler) {
      document.removeEventListener('click', holdFilterDocHandler);
      holdFilterDocHandler = null;
    }
  };

  holdFilterMenu.querySelector('.menu-header button').onclick = (e) => {
    e.stopPropagation();
    closeMenu();
  };

  holdFilterMenu.querySelectorAll('.menu-sort button').forEach(btn => {
    btn.onclick = (e) => {
      e.stopPropagation();
      holdSort = { column, direction: btn.dataset.sort };
      applyHoldFilters();
      closeMenu();
    };
  });

  holdFilterMenu.querySelectorAll('.menu-actions button').forEach(btn => {
    btn.onclick = (e) => {
      e.stopPropagation();
      const action = btn.dataset.action;
      holdFilterMenu.querySelectorAll('.menu-body input[type="checkbox"]').forEach(cb => {
        cb.checked = action === 'select-all';
      });
    };
  });

  holdFilterMenu.querySelector('.menu-footer .clear-btn').onclick = (e) => {
    e.stopPropagation();
    holdFilters[column] = new Set();
    applyHoldFilters();
    closeMenu();
  };

  holdFilterMenu.querySelector('.menu-footer .apply-btn').onclick = (e) => {
    e.stopPropagation();
    const selectedValues = new Set();
    holdFilterMenu.querySelectorAll('.menu-body input[type="checkbox"]').forEach(cb => {
      if (cb.checked) selectedValues.add(normalizeFilterValue(column, cb.value));
    });
    holdFilters[column] = selectedValues;
    applyHoldFilters();
    closeMenu();
  };

  holdFilterDocHandler = function onDocClick(evt) {
    if (holdFilterMenu && !holdFilterMenu.contains(evt.target) && evt.target !== button) {
      closeMenu();
    }
  };
  document.addEventListener('click', holdFilterDocHandler);
}

function findPathToAccount(accountNumber) {
  if (!currentRoot || !accountNumber) return null;
  const target = String(accountNumber).trim();
  const stack = [{ node: currentRoot, path: [currentRoot] }];

  while (stack.length > 0) {
    const { node, path } = stack.pop();
    const name = node?.data?.name ? String(node.data.name).trim() : '';
    if (name === target) return path;

    const next = [];
    if (node.children) next.push(...node.children);
    if (node._children) next.push(...node._children);

    next.forEach(child => stack.push({ node: child, path: [...path, child] }));
  }
  return null;
}

function expandNodesInPath(path) {
  if (!path) return;
  path.forEach(n => {
    if (n._children) {
      n.children = n._children;
      n._children = null;
    }
  });
}

function highlightHoldNode(accountNumber) {
  if (!g || !accountNumber) return;
  g.selectAll('.node rect').classed('hold-highlight', false);
  g.selectAll('.node').each(function (d) {
    const name = d?.data?.name ? String(d.data.name).trim() : '';
    if (name === String(accountNumber).trim()) {
      d3.select(this).select('rect').classed('hold-highlight', true);
    }
  });
}

function expandHoldAccount(accountNumber) {
  const path = findPathToAccount(accountNumber);
  if (!path) {
    alert('Account not found in the current graph.');
    return;
  }
  expandNodesInPath(path);
  drawTree(currentRoot);
  highlightHoldNode(accountNumber);
}

function cleanTreeData(root) {
  // Remove children with null or undefined accounts recursively (keep empty strings, "N/A", or "NA" as valid placeholders)
  if (!root || !root.children) return;
  root.children = root.children.filter(child => {
    if (!child || typeof child !== 'object' || !child.data) return false;
    const name = child.data.name;
    // Exclude only if name is null or undefined
    if (name === null || name === undefined) return false;
    // Recursively clean descendants
    cleanTreeData(child);
    return true;
  });
}

function resizeTree() {
  const headerH = document.querySelector('header')?.clientHeight || 0;
  width = window.innerWidth;
  height = window.innerHeight - headerH;
  svg.attr('width', width).attr('height', height);
}
window.addEventListener('resize', () => {
  resizeTree();
  drawTree(currentRoot);
});
resizeTree();

fetch(`/graph_data/${ackNo}`)
  .then(res => {
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return res.json();
  })
  .then(data => {
    if (!data || data.error) {
      const chartEl = document.getElementById('chart');
      if (chartEl) {
        const message = data.error || 'No graph data found for this Acknowledgement No.';
        chartEl.innerHTML = `<div style="text-align:center; padding:50px; font-size:18px; color:#666;">${message}</div>`;
      }
      return;
    }
    window.graphData = data; // Set global for statewise summary modal

    // Deep clean the data before creating hierarchy
    function deepCleanData(node) {
      if (!node || typeof node !== 'object') return null;
      if (node.children) {
        node.children = node.children.map(deepCleanData).filter(Boolean);
      }
      return node;
    }

    const cleanedData = deepCleanData(data);
    if (!cleanedData || !cleanedData.children || cleanedData.children.length === 0) {
      console.log('No valid graph data found - cleanedData:', cleanedData);
      const chartEl = document.getElementById('chart');
      if (chartEl) {
        chartEl.innerHTML = '<div style="text-align:center; padding:50px; font-size:18px; color:#666;">No valid graph data found for this Acknowledgement No.</div>';
      }
      return;
    }

    const root = d3.hierarchy(cleanedData);
    if (!root || !root.children || root.children.length === 0) {
      const chartEl = document.getElementById('chart');
      if (chartEl) {
        chartEl.innerHTML = '<div style="text-align:center; padding:50px; font-size:18px; color:#666;">No valid graph data found for this Acknowledgement No.</div>';
      }
      return;
    }

    // No sanitization needed - let D3 handle the data as is

    if (!root.children || root.children.length === 0) {
      const chartEl = document.getElementById('chart');
      if (chartEl) {
        chartEl.innerHTML = '<div style="text-align:center; padding:50px; font-size:18px; color:#666;">No valid graph data found for this Acknowledgement No.</div>';
      }
      return;
    }

    cleanTreeData(root);
    bfsAssignLayers(root);
    if (!root.children || root.children.length === 0) {
      const chartEl = document.getElementById('chart');
      if (chartEl) {
        chartEl.innerHTML = '<div style="text-align:center; padding:50px; font-size:18px; color:#666;">No valid graph data found for this Acknowledgement No.</div>';
      }
      return;
    }
    root.descendants().forEach(d => {
      if (d.depth > 0) {
        d._children = d.children;
        d.children = null;
      }
    });
    let count = 1;
    root.children?.forEach(child => {
      child.data.victim_label = `Victim ${count++}`;
    });
    currentRoot = root;
    populateBranchNames(root).then(() => {
      drawTree(root);
      setTimeout(() => drawTree(root), 80);
    });
  })
  .catch(error => {
    console.error('Error fetching graph data:', error);
    const chartEl = document.getElementById('chart');
    if (chartEl) {
      let errorMessage = 'Error loading graph data. Please try again later.';
      if (error.message.includes('500')) {
        errorMessage = 'Server error occurred while processing graph data. Please contact support.';
      } else if (error.message.includes('404')) {
        errorMessage = 'Graph data not found. Please check the Acknowledgement No.';
      }
      chartEl.innerHTML = `<div style="text-align:center; padding:50px; font-size:18px; color:#666;">${errorMessage}</div>`;
    }
  });

function bfsAssignLayers(root) {
  if (!root || !root.data) return;
  const queue = [root];
  root.data.layer = 1;
  while (queue.length > 0) {
    const node = queue.shift();
    if (!node || !node.data) continue;
    const currentLayer = node.data.layer || 1;
    if (node.children) {
      node.children.forEach(child => {
        if (!child || !child.data) return;
        child.data.layer = currentLayer + 1;
        queue.push(child);
      });
    }
  }
  // Ensure all descendants have a layer
  if (root.descendants) {
    root.descendants().forEach(d => {
      if (d && d.data && !d.data.layer) d.data.layer = 1;
    });
  }
}
// 🧮 Helper: calculate total repeated transaction amount
function getTotalRepeatedAmount(txns) {
  if (!txns || txns.length === 0) return 0;

  const uniqueTxns = Array.from(
    new Map(txns.map(txn => [txn.txn_id, txn])).values()
  );

  return uniqueTxns.reduce((sum, txn) => sum + (parseFloat(txn.amount) || 0), 0);
}

function toggleCollapse(d) {
  if (d.children) {
    d._children = d.children;
    d.children = null;
  } else if (d._children) {
    d.children = d._children;
    d._children = null;
  }
}

/**
 * Toggle expansion for the whole tree.
 * When expanded, every non-burst node reveals its children.
 * When collapsed, we hide children for all non-root nodes.
 */
function toggleExpandAllNodes() {
  if (!currentRoot) return false;
  expandAllActive = !expandAllActive;

  const applyState = (node, expand) => {
    if (!node) return;

    // Skip burst nodes to respect existing UX rule
    if (node.depth > 0 && !node.burst) {
      if (expand) {
        if (node._children) node.children = node._children;
      } else {
        if (node.children) node._children = node.children;
        node.children = null;
      }
    }

    // Traverse using whichever children collection exists
    const next = node.children || node._children || [];
    next.forEach(child => applyState(child, expand));
  };

  applyState(currentRoot, expandAllActive);
  drawTree(currentRoot);

  // Update button title to reflect the opposite action
  const btn = document.getElementById('expandAllBtn');
  if (btn) {
    btn.title = expandAllActive ? 'Collapse All Nodes' : 'Expand All Nodes';
    btn.setAttribute('aria-label', btn.title);
  }

  return expandAllActive;
}

function drawTree(root) {
  if (!root || !root.children || root.children.length === 0) return;
  g.selectAll('*').remove();
  const layerHeight = 150;
  const maxLayer = d3.max(root.descendants(), d => d?.data?.layer || 1) || 1;
  const requiredHeight = (maxLayer * layerHeight) + 200;
  svg.attr('height', Math.max(height, requiredHeight));
  try {
    root.each(d => {
      if (!d || !d.data || !d.data.layer) return;
      d.y = (d.data.layer - 1) * layerHeight;
    });
    const treeLayout = d3.tree().nodeSize([300, 200]);
    treeLayout(root);
  } catch (error) {
    console.error('Error in drawTree:', error);
    const chartEl = document.getElementById('chart');
    if (chartEl) {
      chartEl.innerHTML = '<div style="text-align:center; padding:50px; font-size:18px; color:#666;">Error rendering graph. Please check the data.</div>';
    }
    return;
  }

  g.selectAll('.link')
    .data(root.links())
    .join('path')
    .attr('class', 'link')
    .attr('d', d3.linkVertical().x(d => d.x).y(d => d.y))
    .attr('stroke', '#888')
    .attr('stroke-width', 1.5)
    .attr('fill', 'none');

  const nodes = g.selectAll('.node')
    .data(root.descendants())
    .join('g')
    .attr('class', 'node')
    .attr('transform', d => `translate(${d.x},${d.y})`);

  let victimCounter = 1;

  // Helper to append centered, evenly-spaced lines of text inside the node
  function appendCenteredLines(container, lines, options = {}) {
    const lineHeight = options.lineHeight || 16;
    const startY = options.startY !== undefined
      ? options.startY
      : -((lines.length - 1) / 2) * lineHeight;

    lines.forEach((ln, idx) => {
      const t = container.append('text')
        .attr('x', 0)
        .attr('y', startY + idx * lineHeight)
        .attr('text-anchor', 'middle')
        .text(ln.text || '');

      if (ln.class) t.attr('class', ln.class);
      if (ln.size) t.style('font-size', ln.size + 'px');
      if (ln.weight) t.style('font-weight', ln.weight);
      if (ln.fill) t.style('fill', ln.fill);
    });
  }
  nodes.each(function (d) {
    const n = d3.select(this);
    if (!d || !d.data || !d.data.layer) return;
    const boxWidth = 250, boxHeight = 100;

    n.append('rect')
      .attr('x', -boxWidth / 2)
      .attr('y', -boxHeight / 2)
      .attr('width', boxWidth)
      .attr('height', boxHeight)
      .attr('rx', 14)
      .attr('fill', d => {
        const isLeafNode = !d.children && !d._children;
        if (isLeafNode && !d.burst) return '#15803d';
        return layerColors[d.data.layer] || '#ccc';
      })
      .attr('stroke', d.data.hold_info ? '#dc2626' : '#1e293b')
      .attr('stroke-width', d.data.hold_info ? 3 : 1.5)
      .style('filter', d.data.hold_info
        ? 'drop-shadow(0 0 8px rgba(220, 38, 38, 0.7))'
        : 'drop-shadow(2px 2px 6px rgba(0,0,0,0.15))');

    n.selectAll('text').remove();

    if (d.depth === 0) {
      appendCenteredLines(n, [
        { text: 'Acknowledgement No', size: 13, weight: 'bold', fill: '#000' },
        { text: ackNo, size: 13, fill: '#000' }
      ], { lineHeight: 22 });
    }

    if (d.depth === 1) {
      const victimNo = victimCounter++;
      appendCenteredLines(n, [
        { text: `Victim Account No: ${victimNo}`, size: 13, weight: 'bold', fill: '#000' },
        { text: `Acc No: ${d.data.name || 'N/A'}`, size: 12, fill: '#000' },
        { text: `Bank: ${d.data.action || d.data.bank || 'Unknown Bank'}`, size: 12, fill: '#1f2937' }
      ], { lineHeight: 18 });

    }

    if (d.data.layer > 2) {

 const txsFromParent = (d && d.data && Array.isArray(d.data.transactions_from_parent)) ? d.data.transactions_from_parent : [];
 const isRepeated = txsFromParent.length > 1;

 // ✅ Remove old amount before adding new
  n.selectAll(".amt-text").remove();

    // Build the lines for deeper layers and append centered
    const deepLines = [];
    deepLines.push({ text: `Acc No: ${d.data.name ?? 'Acc ?'}`, size: 13, weight: 'bold', fill: '#000' });
    if (d.data.bank) deepLines.push({ text: `Bank: ${d.data.bank}`, size: 12, fill: '#000' });
    deepLines.push({ text: `IFSC Code: ${d.data.ifsc}`, size: 12, fill: '#1f2937' });

    const branchLabel = d.data.branch || branchCache.get(d.data.ifsc) || 'Unknown';
    deepLines.push({ text: `Branch: ${branchLabel}`, size: 12, fill: '#1f2937', class: 'branch-text' });

    // Only show amount when not repeated
    // isRepeated computed above
    if (!isRepeated) {
      const amount = Number(d.data.amt || 0).toLocaleString('en-IN');
      deepLines.push({ text: `Amt: ₹${amount}`, size: 12, fill: '#000', class: 'amt-text' });
    }

    appendCenteredLines(n, deepLines, { lineHeight: 16 });
  
  // If branch is not available yet, fetch it and update the text element
  if (d.data.ifsc && !d.data.branch && !branchCache.get(d.data.ifsc)) {
    fetchBranchInfo(d.data.ifsc).then(branchData => {
      const branchName = branchCache.get(d.data.ifsc) || branchData?.BRANCH || 'Unknown';
      d.data.branch = branchName;
      // Update the specific text element
      branchText.text(`Branch: ${branchName}`);
    });
  }

}

    // Adjust box width and text sizing to prevent overflow
    try {
      const padding = 24;
      let maxTextWidth = 0;
      n.selectAll('text').each(function () {
        const bbox = this.getBBox();
        if (bbox && bbox.width > maxTextWidth) maxTextWidth = bbox.width;
      });
      const currentRect = n.select('rect');
      let adjustedWidth = Math.max(250, Math.min(maxTextWidth + padding, 360));
      currentRect.attr('x', -adjustedWidth / 2).attr('width', adjustedWidth);

      // Reduce font-size for any line still exceeding the box
      n.selectAll('text').each(function () {
        const el = d3.select(this);
        const w = this.getBBox().width;
        const limit = adjustedWidth - padding;
        if (w > limit) {
          const fs = parseFloat(el.style('font-size')) || 12;
          const ratio = Math.max(0.75, Math.min(1, limit / w));
          const newFs = Math.max(10, Math.floor(fs * ratio));
          el.style('font-size', `${newFs}px`);
        }
      });

      // Final fit for branch line if needed
      const branchSel = n.select('.branch-text');
      if (!branchSel.empty()) {
        const w = branchSel.node().getBBox().width;
        const limit = adjustedWidth - padding;
        if (w > limit) {
          branchSel.attr('lengthAdjust', 'spacingAndGlyphs').attr('textLength', limit);
        }
      }
    } catch (e) {
      // silently ignore sizing errors
    }

    const iconData = [];

    if (d.data.atm_info) {
      iconData.push({
        emoji: '💳', onClick: () => {
          leftContent.innerHTML =
            `<strong>ATM Withdrawal</strong><br>` +
            `Account: ${d.data.name}<br>` +
            `ATM ID: ${d.data.atm_info.atm_id}<br>` +
            (d.data.atm_info.location ? `ATM Location: ${d.data.atm_info.location}<br>` : '') +
            `Amount: ₹${d.data.atm_info.amount}<br>` +
            `Date: ${d.data.atm_info.date}`;
          leftPanel.style.display = 'block';
        }
      });
    }


    // 💥: Burst transaction node (20+ children)
    const totalChildren = (d.children?.length || 0) + (d._children?.length || 0);

    if (d.burst || totalChildren >= 20) {
      if (!d.burst) {
        d.burst = true;
        // Disable expanding this node
        d._children = null;
        d.children = null;
      }
      iconData.push({
        emoji: '💥',
        onClick: () => {
          leftContent.innerHTML = `
           <strong>Burst Transaction Alert</strong><br><br>
           This node has ${totalChildren} child transactions.<br>
           To avoid graph clutter, expansion is disabled.
         `;
          leftPanel.style.display = 'block';
        }
      });
    }

    if (d.data.hold_info) {
      iconData.push({
        emoji: '🔒',
        onClick: () => {
          // Get path from root to this hold node
          const path = [];
          let current = d;
          while (current) {
            path.unshift(current);
            current = current.parent;
          }

          // Victim AccNo is the first victim's account (depth 1)
          const victimAccNo = path[1] ? path[1].data.name || 'N/A' : 'N/A';

          const formSectionId = 'holdFormFields';
          const toggleBtnId = 'openHoldFormBtn';

          let html = `<div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">`;
          html += `<strong style="margin:0;">Hold Transaction Details</strong>`;
          // small doc-style icon (from screenshot) to toggle the court/refund form
          html += `<button id="${toggleBtnId}" title="Show/Hide court & refund info" aria-label="Show or hide court and refund info" aria-expanded="false" style="background:#ede9fe; border:1px solid #c4b5fd; border-radius:8px; width:32px; height:32px; display:flex; align-items:center; justify-content:center; cursor:pointer; padding:0; box-shadow: inset 0 0 0 1px #e5e7eb;">`;
          html += `<svg viewBox="0 0 32 40" width="18" height="22" aria-hidden="true" focusable="false">`;
          html += `<rect x="4" y="4" width="24" height="32" rx="2" ry="2" fill="#ede9fe" stroke="#c4b5fd" stroke-width="2"></rect>`;
          html += `<rect x="8" y="10" width="12" height="2" fill="#a78bfa"></rect>`;
          html += `<rect x="8" y="16" width="16" height="2" fill="#a78bfa"></rect>`;
          html += `<rect x="8" y="22" width="14" height="2" fill="#a78bfa"></rect>`;
          html += `<rect x="8" y="28" width="10" height="2" fill="#a78bfa"></rect>`;
          html += `</svg>`;
          html += `</button>`;
          html += `</div>`;
          html += `<strong>Layer:</strong> ${d.data.layer - 2 || 'N/A'}<br>`;
          html += `<strong>Victim Acc No:</strong> ${victimAccNo}<br>`;
          html += `<strong>Put on hold Acc no:</strong> ${d.data.name || 'N/A'}<br>`;
          html += `<strong>Put on hold by:</strong> ${d.data.bank || 'N/A'}<br>`;
          html += `<strong>Put on hold Amount:</strong> ₹${d.data.hold_info.amount}<br>`;
          // Court/Refund fields styled similarly to the right-side modal; hidden until icon click
          html += `<div id="${formSectionId}" style="display:none; margin-top:12px; padding:10px 0; border-top:1px solid #e5e7eb;">`;
          html += `<div style="margin-bottom:8px;"><label style="font-weight:600; display:block; margin-bottom:4px;">Court Order Date:</label><input id="holdCourtDate" type="date" style="width:100%; padding:6px 8px; border:1px solid #cbd5e1; border-radius:6px;"></div>`;
          html += `<div style="margin-bottom:8px;"><label style="font-weight:600; display:block; margin-bottom:4px;">Status of Refund:</label><select id="holdRefundStatus" style="width:100%; padding:6px 8px; border:1px solid #cbd5e1; border-radius:6px;"><option value="Refunded">Refunded</option><option value="Partially Refunded">Partially Refunded</option><option value="Not Refunded">Not Refunded</option></select></div>`;
          html += `<div style="margin-bottom:8px;"><label style="font-weight:600; display:block; margin-bottom:4px;">Amount Refund:</label><input id="holdRefundAmount" type="text" inputmode="decimal" placeholder="₹" style="width:100%; padding:6px 8px; border:1px solid #cbd5e1; border-radius:6px;"></div>`;
          html += `<div style="display:flex; gap:8px; margin-top:4px;">`;
          html += `<button id="editHoldExtraBtn" type="button" style="flex:1; background:#6b7280; color:white; border:none; padding:10px 16px; border-radius:8px; cursor:pointer; font-weight:600;">Edit</button>`;
          html += `<button id="saveHoldExtraBtn" style="flex:1; background:#2563eb; color:white; border:none; padding:10px 16px; border-radius:8px; cursor:pointer; font-weight:600;">Save</button>`;
          html += `</div>`;
          html += `</div>`;
          // Add PDF button
          html += `<br><button id="downloadHoldGraphPdfBtn" style="background:#10b981; color:white; border:none; padding:8px 16px; border-radius:4px; cursor:pointer;">🖨️ Download Fundtrail</button>`;
          leftContent.innerHTML = html;
          leftPanel.style.display = 'block';

          const formSection = document.getElementById(formSectionId);
          const toggleBtn = document.getElementById(toggleBtnId);
          const courtInput = document.getElementById('holdCourtDate');
          const statusSelect = document.getElementById('holdRefundStatus');
          const amountInput = document.getElementById('holdRefundAmount');
          const saveHoldBtn = document.getElementById('saveHoldExtraBtn');
          const editHoldBtn = document.getElementById('editHoldExtraBtn');

          const holdInfo = d.data.hold_info || {};

          // Prefill existing values if already saved
          if (courtInput && holdInfo.court_order_date) {
            courtInput.value = holdInfo.court_order_date;
          }
          if (statusSelect && holdInfo.refund_status) {
            statusSelect.value = holdInfo.refund_status;
          }
          if (amountInput && holdInfo.refund_amount != null) {
            const amtNum = Number(holdInfo.refund_amount) || 0;
            amountInput.dataset.rawValue = String(amtNum);
            amountInput.value = amtNum.toLocaleString('en-IN');
          }

          // Format amount with commas as user types (Indian locale)
          function attachAmountFormatter(inputEl) {
            if (!inputEl) return;
            inputEl.addEventListener('input', () => {
              const cleaned = inputEl.value.replace(/[^\d.]/g, '').replace(/,/g, '');
              if (!cleaned) {
                inputEl.dataset.rawValue = '';
                inputEl.value = '';
                return;
              }
              const num = Number(cleaned);
              if (!Number.isFinite(num)) {
                return;
              }
              inputEl.dataset.rawValue = String(num);
              inputEl.value = num.toLocaleString('en-IN');
            });
          }

          attachAmountFormatter(amountInput);

          // Viewer: disable hold form inputs and hide save/edit buttons
          if (isViewer) {
            [courtInput, statusSelect, amountInput].forEach(el => { if (el) el.disabled = true; });
            if (saveHoldBtn) saveHoldBtn.style.display = 'none';
            if (editHoldBtn) editHoldBtn.style.display = 'none';
          }

          // Edit button: allow enabling the input boxes when not a viewer
          if (editHoldBtn && !isViewer) {
            editHoldBtn.onclick = () => {
              [courtInput, statusSelect, amountInput].forEach(el => {
                if (el) el.disabled = false;
              });
            };
          }

          if (toggleBtn && formSection) {
            toggleBtn.onclick = () => {
              const isHidden = formSection.style.display === 'none' || formSection.style.display === '';
              formSection.style.display = isHidden ? 'block' : 'none';
              toggleBtn.setAttribute('aria-expanded', isHidden ? 'true' : 'false');
            };
          }

          // Save court / refund details
          if (saveHoldBtn && !isViewer) {
            saveHoldBtn.onclick = () => {
              const rawAmt = amountInput ? (amountInput.dataset.rawValue || amountInput.value.replace(/,/g, '').replace(/[^\d.]/g, '')) : '';
              const amtVal = rawAmt ? Number(rawAmt) : null;

              const payload = {
                ack_no: ackNo,
                hold_txn_id: holdInfo.txn_id,
                court_order_date: courtInput ? courtInput.value : null,
                refund_status: statusSelect ? statusSelect.value : null,
                refund_amount: amtVal,
              };

              fetch('/save_hold_refund', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
              })
                .then(res => res.json().then(data => ({ ok: res.ok, data })))
                .then(({ ok, data }) => {
                  if (!ok || data.status !== 'success') {
                    alert(data.message || 'Failed to save refund details.');
                    return;
                  }

                  // Update in-memory data so it reflects without reload
                  d.data.hold_info.court_order_date = payload.court_order_date;
                  d.data.hold_info.refund_status = payload.refund_status;
                  d.data.hold_info.refund_amount = payload.refund_amount;

                  [courtInput, statusSelect, amountInput].forEach(el => {
                    if (el) el.disabled = true;
                  });

                  alert('Refund details saved successfully.');
                })
                .catch(() => {
                  alert('Failed to save refund details.');
                });
            };
          }

          // Attach click
          document.getElementById('downloadHoldGraphPdfBtn').onclick = () => {
            downloadHoldGraphPdf(path, ackNo);
          };
        }
      });
    }

    if (d.data.cheque_info) {
      iconData.push({
        emoji: '🎫', onClick: () => {
          leftContent.innerHTML =
            `<strong>Cheque Withdrawal</strong><br>` +
            `Account: ${d.data.name}<br>` +
            `Cheque No: ${d.data.cheque_info.cheque_no}<br>` +
            `Amount: ₹${d.data.cheque_info.amount}<br>` +
            `IFSC: ${d.data.cheque_info.ifsc}<br>` +
            `Date: ${d.data.cheque_info.date}`;
          leftPanel.style.display = 'block';
        }
      });
    }

    if (d.data.incomingFrom && d.data.incomingFrom.length > 1) {
      iconData.push({
        emoji: '📥',
        onClick: () => {
          const incoming = d.data.incomingFrom;
          let html = `<strong>Received from ${incoming.length} Accounts</strong><br><br>`;
          html += incoming.map(item =>
            `<div class="detail-row">
              <b>From:</b> ${item.from || '—'}<br>
              <b>Amt:</b> ₹${item.amount || '0.0'}<br>
              <b>Date:</b> ${item.date || '—'}<br>
            </div><hr>`
          ).join('');
          leftContent.innerHTML = html;
          leftPanel.style.display = 'block';
        }
      });
    }

    // 🌀 Handle repeated transactions between parent-child nodes
    // ✅ Only calculate and show total amount if there are multiple transactions
    if (d.data.transactions_from_parent && d.data.transactions_from_parent.length > 1) {
      const txns = d.data.transactions_from_parent;
      const totalAmount = getTotalRepeatedAmount(txns);

      // Remove previous amount display if exists
      n.selectAll(".node-amount").remove();

      // 💰 Show transaction amount (existing line)
      n.append("text")
        .attr("class", "node-amount current")
        .attr("x", 0)
        .attr("y", 42) // Adjust vertical position as needed
        .attr("text-anchor", "middle")
        .style("font-size", "13px")
        .style("fill", "#222")
        .text(`Total amt  ₹${ totalAmount.toLocaleString('en-IN') }`);
      // 🔁 Add repeated icon
      iconData.push({
        emoji: "🔁",
        onClick: () => {
          let txnHTML = `
        <strong>${txns.length} Transactions between nodes</strong><br>
        <b>Total Amount:</b> ₹${totalAmount.toLocaleString('en-IN')}<br><br>
      `;
          txnHTML += txns.map(txn => `
        <div class="detail-row">
          <b>Txn ID:</b> ${txn.txn_id}<br>
          <b>Amount:</b> ₹${txn.amount}<br>
          <b>Date:</b> ${txn.date}<br>
        </div><hr>
      `).join("");
          leftContent.innerHTML = txnHTML;
          leftPanel.style.display = "block";
        }
      });
    }

    // === Icon placement logic ===
    const spacing = 32;
    const startX = -(spacing * (iconData.length - 1)) / 2;
    const iconY = boxHeight / 2 + 10;

    iconData.forEach((icon, i) => {
      const x = startX + i * spacing;
      addIcon(n, x, iconY, icon.emoji, icon.onClick);
    });


    let clickTimer;
    n.on('click', function (event) {
      if (event.target.classList.contains('icon')) return;
      if (d.burst) return;
      clearTimeout(clickTimer);
      clickTimer = setTimeout(() => {
        toggleCollapse(d);
        drawTree(currentRoot);
      }, 250);
    }).on('dblclick', () => {
      event.stopPropagation();
      clearTimeout(clickTimer);
      if (d.data.ifsc) {
        // Use a safe ID (replace non-alphanumeric characters)
        const safeId = `branch-${String(d.data.name || '').replace(/[^a-zA-Z0-9_-]/g, '')}`;

        const isRepeated = Array.isArray(d.data.transactions_from_parent) && d.data.transactions_from_parent.length > 1;
        let baseHtml =
          `<div class="detail-row"><span class="label">Layer:</span> ${d.data.layer - 2 || '—'}</div>` +
          `<div class="detail-row"><span class="label">Account:</span> ${d.data.name || '—'}</div>` +
          `<div class="detail-row"><span class="label">IFSC:</span> ${d.data.ifsc || '—'}</div>` +
          `<div class="detail-row" id="${safeId}"><span class="label">Branch:</span> ${d.data.branch || branchCache.get(d.data.ifsc) || 'Unknown'}</div>` +
          `<div class="detail-row"><span class="label">Bank/FI:</span> ${d.data.bank || '—'}</div>`;
        if (!isRepeated) {
          baseHtml +=
            `<div class="detail-row"><span class="label">Date:</span> ${d.data.date || '—'}</div>` +
            `<div class="detail-row"><span class="label">Txn ID:</span> ${d.data.txid || '—'}</div>` +
            `<div class="detail-row"><span class="label">Amount:</span> ₹${d.data.amt || '0.0'}</div>` +
            `<div class="detail-row"><span class="label">Disputed:</span> ₹${d.data.disputed || '0.0'}</div>`;
        }
        detailsContent.innerHTML = baseHtml;
        
        // Setup KYC section with current transaction data
        const kycSection = document.getElementById('kycDetailsSection');
        const kycTxnId = document.getElementById('kycTxnId');
        const kycName = document.getElementById('kycName');
        const kycAadhar = document.getElementById('kycAadhar');
        const kycMobile = document.getElementById('kycMobile');
        const kycAddress = document.getElementById('kycAddress');
        const saveKycBtn = document.getElementById('saveKycBtn');
        const editKycBtn = document.getElementById('editKycBtn');
        const kycForm = document.getElementById('kycForm');
        
        // Hide KYC section by default when new transaction is selected
        if (kycSection) {
          kycSection.style.display = "none";
        }
        
        // Update form values with current transaction data
        if (kycTxnId) kycTxnId.value = d.data.txid || '';
        if (kycName) kycName.value = d.data.kyc_name || '';
        if (kycAadhar) kycAadhar.value = d.data.kyc_aadhar || '';
        if (kycMobile) kycMobile.value = d.data.kyc_mobile || '';
        if (kycAddress) kycAddress.value = d.data.kyc_address || '';
        
        // Function to disable KYC inputs
        const disableKycInputs = () => {
          ['kycName', 'kycAadhar', 'kycMobile', 'kycAddress'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.disabled = true;
          });
          if (saveKycBtn) saveKycBtn.style.display = "none";
          if (editKycBtn && !isViewer) editKycBtn.style.display = "block";
        };
        
        // Function to enable KYC inputs
        const enableKycInputs = () => {
          ['kycName', 'kycAadhar', 'kycMobile', 'kycAddress'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.disabled = false;
          });
          if (saveKycBtn) saveKycBtn.style.display = "block";
          if (editKycBtn) editKycBtn.style.display = "none";
        };
        
        // If viewer, disable KYC editing entirely
        if (isViewer) {
          disableKycInputs();
          if (editKycBtn) editKycBtn.style.display = "none";
        } else {
          // Always disable inputs by default (Edit button will enable them)
          disableKycInputs();
          
          // Add Edit button click handler
          if (editKycBtn) {
            editKycBtn.onclick = null; // Remove old handler
            editKycBtn.onclick = () => {
              enableKycInputs();
            };
          }
        }
        
        // Remove existing form submit listener if any, then add new one
        if (kycForm) {
          // Create a new form handler function for this transaction
          const formHandler = (e) => {
            if (isViewer) {
              e.preventDefault();
              return;
            }
            e.preventDefault();
            const txnId = document.getElementById('kycTxnId')?.value || '';
            const name = document.getElementById('kycName')?.value || '';
            const aadhar = document.getElementById('kycAadhar')?.value || '';
            const mobile = document.getElementById('kycMobile')?.value || '';
            const address = document.getElementById('kycAddress')?.value || '';

            fetch("/save_kyc", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ txn_id: txnId, name, aadhar, mobile, address }),
            })
              .then((res) => res.json())
              .then((data) => {
                if (data.status === "success") {
                  alert("KYC saved successfully!");
                  d.data.kyc_name = name;
                  d.data.kyc_aadhar = aadhar;
                  d.data.kyc_mobile = mobile;
                  d.data.kyc_address = address;
                  // Disable inputs after saving and show Edit button
                  ['kycName', 'kycAadhar', 'kycMobile', 'kycAddress'].forEach(id => {
                    const el = document.getElementById(id);
                    if (el) el.disabled = true;
                  });
                  const saveBtn = document.getElementById('saveKycBtn');
                  const editBtn = document.getElementById('editKycBtn');
                  if (saveBtn) saveBtn.style.display = "none";
                  if (editBtn && !isViewer) editBtn.style.display = "block";
                } else {
                  alert("Error saving KYC: " + data.message);
                }
              });
          };
          
          // Remove old listener and add new one
          kycForm.onsubmit = null;
          kycForm.addEventListener("submit", formHandler);
        }
      }

      detailsPanel.style.display = 'block';
      if (d.data.ifsc) {
        const branchEl = document.getElementById(safeId);
        const cached = d.data.branch || branchCache.get(d.data.ifsc);
        if (cached && branchEl) {
          branchEl.innerHTML = `<span class="label">Branch:</span> ${cached}`;
        } else {
          fetchBranchInfo(d.data.ifsc).then(branchData => {
            const branchName = branchCache.get(d.data.ifsc) || branchData?.BRANCH || 'Not found';
            d.data.branch = branchName;
            if (branchEl) branchEl.innerHTML = `<span class="label">Branch:</span> ${branchName}`;
          });
        }
      }
    });
  });

  // ✅ Center the tree only on the first draw
  if (isFirstDraw) {
    const initialScale = 1.0;
    const centerX = (width / 2) - root.x;
    const centerY = 80;

    svg.transition().duration(750).call(
      d3.zoom().on('zoom', e => g.attr('transform', e.transform))
        .transform,
      d3.zoomIdentity.translate(centerX, centerY).scale(initialScale)
    );

    isFirstDraw = false;
  }
}
function addIcon(container, x, y, emoji, onClick) {
  container.append('circle')
    .attr('cx', x).attr('cy', y).attr('r', 14)
    .attr('fill', '#ffffffcc').attr('stroke', '#1e293b').attr('stroke-width', 1);
  container.append('text')
    .attr('x', x).attr('y', y + 5).attr('text-anchor', 'middle')
    .attr('class', 'icon')
    .style('font-size', '18px').style('cursor', 'pointer').style('fill', '#000')
    .text(emoji).on('click', onClick);
}
// 🧮 Helper: calculate total repeated transaction amount
function getTotalRepeatedAmount(txns) {
  if (!txns || txns.length === 0) return 0;

  const uniqueTxns = Array.from(
    new Map(txns.map(txn => [txn.txn_id, txn])).values()
  );

  return uniqueTxns.reduce((sum, txn) => sum + (parseFloat(txn.amount) || 0), 0);
}

// Add event listener for Download PDF button (using pdfmake)
(function () {
  const downloadBtn = document.getElementById('downloadDetailsPdf');
  if (!downloadBtn) return;

  function attachListener() {
    if (typeof pdfMake !== 'undefined') {
      console.log('pdfMake library loaded successfully.');
      downloadBtn.addEventListener('click', async function () {
        console.log('Download PDF button clicked.');
        const element = document.getElementById('detailsContent');
        if (!element || element.innerHTML.trim() === '') {
          console.log('No content to download.');
          alert('No transaction details available to download.');
          return;
        }
        console.log('Details element found, innerHTML length:', element.innerHTML.length);

        // Parse details from .detail-row elements
        console.log('Starting to query .detail-row elements.');
        const detailRows = element.querySelectorAll('.detail-row');
        console.log('Found', detailRows.length, 'detail rows.');
        const rows = [];
        detailRows.forEach((row, index) => {
          console.log(`Processing row ${index}:`, row);
          const labelSpan = row.querySelector('.label');
          if (labelSpan) {
            const labelText = labelSpan.textContent.trim();
            const fullText = row.textContent.trim();
            const valueText = fullText.replace(labelText, '').trim();
            console.log(`Row ${index} label: "${labelText}", value: "${valueText}"`);
            if (valueText) {
              rows.push([labelText, valueText]);
            }
          }
        });

        if (rows.length === 0) {
          console.log('No rows parsed, alerting.');
          alert('No transaction details available to download.');
          return;
        }

        console.log('Parsed', rows.length, 'detail rows:', rows);

        // Load logo as base64 for PDF
        const logoUrl = window.location.origin + '/static/tn_police_logo.png';
        let logoBase64 = null;
        try {
          const response = await fetch(logoUrl);
          const blob = await response.blob();
          const reader = new FileReader();
          logoBase64 = await new Promise((resolve) => {
            reader.onloadend = () => resolve(reader.result);
            reader.readAsDataURL(blob);
          });
          console.log('Logo loaded for PDF.');
        } catch (error) {
          console.warn('Failed to load logo for PDF:', error);
        }

        const currentDate = new Date().toLocaleDateString('en-IN', { year: 'numeric', month: 'long', day: 'numeric' });

        const docDefinition = {
          pageSize: 'A4',
          pageOrientation: 'landscape',
          header: function (currentPage, pageCount) {
            return {
              margin: [40, 20, 40, 10],
              columns: [
                {
                  image: logoBase64 ? 'logo' : null,
                  width: 50,
                  alignment: 'left'
                },
                {
                  stack: [
                    { text: 'Fund Trail System', style: 'title' },
                    { text: 'Transaction Details Report', style: 'subtitle' }
                  ],
                  alignment: 'center',
                  margin: [0, 0, 0, 5]
                },
                {
                  text: `Page ${currentPage} of ${pageCount}`,
                  alignment: 'right',
                  style: 'pageNumber'
                }
              ]
            };
          },
          footer: function (currentPage, pageCount) {
            return {
              margin: [40, 10, 40, 20],
              columns: [
                { text: 'Generated on ' + currentDate, alignment: 'left', style: 'footerText' },
                { text: 'Confidential - For Official Use Only', alignment: 'center', style: 'footerText' },
                { text: 'Tamil Nadu Police', alignment: 'right', style: 'footerText' }
              ]
            };
          },
          content: [
            { text: `Acknowledgement No: ${ackNo || 'Unknown'}`, style: 'ackNo', margin: [0, 20, 0, 30] },
            {
              table: {
                headerRows: 1,
                widths: ['*', '*'],
                body: [
                  [{ text: 'Field', style: 'tableHeader' }, { text: 'Value', style: 'tableHeader' }],
                  ...rows.map(row => [row[0], row[1]])
                ]
              },
              layout: {
                fillColor: function (rowIndex) {
                  return (rowIndex === 0) ? '#3b82f6' : ((rowIndex % 2 === 1) ? '#f8fafc' : null);
                },
                hLineColor: function (i, node) { return '#d1d5db'; },
                vLineColor: function (i, node) { return '#d1d5db'; },
                hLineWidth: function (i, node) { return 0.5; },
                vLineWidth: function (i, node) { return 0.5; },
                paddingLeft: function (i, node) { return 8; },
                paddingRight: function (i, node) { return 8; },
                paddingTop: function (i, node) { return 6; },
                paddingBottom: function (i, node) { return 6; }
              },
              margin: [0, 0, 0, 0]
            }
          ],
          styles: {
            title: { fontSize: 16, bold: true, color: '#1f2937' },
            subtitle: { fontSize: 12, bold: false, color: '#6b7280', italics: true },
            ackNo: { fontSize: 14, bold: true, color: '#3b82f6', alignment: 'center' },
            tableHeader: { bold: true, fontSize: 11, color: 'white' },
            pageNumber: { fontSize: 9, color: '#6b7280' },
            footerText: { fontSize: 9, color: '#9ca3af', italics: true }
          },
          defaultStyle: {
            font: 'Roboto',
            fontSize: 10,
            lineHeight: 1.2
          },
          images: {
            logo: logoBase64
          }
        };

        console.log('PDF document definition created.');
        console.log('Calling pdfMake.createPdf.download...');
        pdfMake.createPdf(docDefinition).download(`transaction_details_${ackNo || 'unknown'}.pdf`);
        console.log('PDF download initiated.');
      });
    } else {
      console.log('pdfMake not yet loaded, polling...');
      setTimeout(attachListener, 100);
    }
  }

  attachListener();
})();

function downloadHoldGraphPdf(path, ackNo) {
  // Exclude the root 'Flow' node from the path
  path = path.slice(1);

  const svgNS = "http://www.w3.org/2000/svg";
  const width = 1000;
  const margin = 150;
  const boxWidth = 520;
  const boxHeight = 280;
  const verticalSpacing = 360;

  // Calculate nodes per page: A4 height ~842 points, pdfWidth=350, scale accordingly
  const pdfPageHeight = 842; // A4 height in points
  const pdfWidth = 300;
  const scaleFactor = pdfWidth / width;
  const nodesPerPage = 10; // Fixed to 10 for continuation across pages

  // Split path into chunks
  const chunks = [];
  for (let i = 0; i < path.length; i += nodesPerPage) {
    chunks.push(path.slice(i, i + nodesPerPage));
  }

  // Function to generate SVG for a chunk
  function generateSVG(chunk, startIndex) {
    let height, startY;
    if (chunk.length <= 4) {
      const totalNodeHeight = chunk.length * verticalSpacing;
      height = margin + totalNodeHeight + margin;
      startY = (height - totalNodeHeight) / 2;
    } else {
      height = margin + chunk.length * verticalSpacing + margin;
      startY = margin;
    }
    const svg = document.createElementNS(svgNS, "svg");
    svg.setAttribute("width", width);
    svg.setAttribute("height", height);
    svg.setAttribute("xmlns", svgNS);
    svg.style.background = "#fff";

    // Helper to add multiline centered text
    function addMultilineText(svg, x, y, text, fontSize) {
      const t = document.createElementNS(svgNS, "text");
      t.setAttribute("x", x);
      t.setAttribute("y", y);
      t.setAttribute("text-anchor", "middle");
      t.setAttribute("font-size", String(fontSize));
      t.setAttribute("fill", "#000000");
      t.setAttribute("font-family", "Arial, sans-serif");
      t.style.textShadow = "0 0 2px white";
      const maxLen = 32;
      const lines = [];
      for (let i = 0; i < text.length; i += maxLen) {
        lines.push(text.slice(i, i + maxLen));
      }
      lines.forEach((line, idx) => {
        const tsp = document.createElementNS(svgNS, "tspan");
        tsp.setAttribute("x", x);
        tsp.setAttribute("dy", idx === 0 ? "0" : "1.35em");
        tsp.textContent = line;
        t.appendChild(tsp);
      });
      svg.appendChild(t);
      // return total height occupied
      return fontSize + (lines.length - 1) * (1.35 * fontSize);
    }
    function calcMultilineHeight(text, fontSize) {
      const maxLen = 32;
      const lines = Math.max(1, Math.ceil(text.length / maxLen));
      return fontSize + (lines - 1) * (1.35 * fontSize);
    }

    for (let i = 0; i < chunk.length; i++) {
      const node = chunk[i];
      const globalIndex = startIndex + i;
      const x = width / 2;
      const y = startY + i * verticalSpacing;

      // Pre-calculate text positions to determine required box height
      //const bankName = node.data.action || node.data.bank || 'Unknown Bank';
      //const bankName = node.data.bank || "Unknown Bank";

      let bankName;

      if (globalIndex === 0) {
      // Victim node — pull correct victim bank from the first layer node if needed
         bankName = node.data.action || node.data.bank || 'Unknown Bank';
      } else {
         bankName = node.data.bank || "Unknown Bank";
      }


      const bankBaseY = globalIndex === 0 ? y + 30 : y + 19;

      // Wrap bank name if too long
      const maxLineLength = 25; // Approximate characters per line
      const words = bankName.split(' ');
      let lines = [];
      let currentLine = '';

      words.forEach(word => {
        if ((currentLine + ' ' + word).length <= maxLineLength) {
          currentLine += (currentLine ? ' ' : '') + word;
        } else {
          if (currentLine) lines.push(currentLine);
          currentLine = word;
        }
      });
      if (currentLine) lines.push(currentLine);

      const fontSize = 22;
      const lineHeight = 1.35 * fontSize;
      const bankHeight = fontSize + (lines.length - 1) * lineHeight;
      const nextY = bankBaseY + bankHeight + 10; // Margin after bank text

      const topY = y - 50;
      const paddingBox = 20;
      const singleH = 20;
      const gap = 18;
      const txTextCalc = `Transaction ID: ${node.data.txid || "N/A"}`;
      const txH = calcMultilineHeight(txTextCalc, 18);
      let bottomYCalc;
      if (globalIndex === 0) {
        bottomYCalc = bankBaseY + bankHeight;
      } else if (globalIndex === path.length - 1) {
        const baseY = nextY;
        bottomYCalc = baseY + singleH + gap + singleH + gap + txH + gap + singleH + (node.data.hold_info && node.data.hold_info.amount ? gap + singleH : 0);
      } else {
        const baseY = nextY;
        bottomYCalc = baseY + singleH + gap + singleH + gap + txH + gap + singleH;
      }
      const rectY = topY - paddingBox;
      const dynamicBoxHeight = Math.max((bottomYCalc - topY) + (paddingBox * 2), boxHeight);

      // Draw box with dynamic height aligned to content bounds
      const rect = document.createElementNS(svgNS, "rect");
      rect.setAttribute("x", x - boxWidth / 2);
      rect.setAttribute("y", rectY);
      rect.setAttribute("width", boxWidth);
      rect.setAttribute("height", dynamicBoxHeight);
      rect.setAttribute("rx", 14);
      rect.setAttribute("fill", globalIndex === 0 ? "#a7f3d0" : (globalIndex === path.length - 1 ? "#f86262ff " : "#fcfaf9ff"));
      rect.setAttribute("stroke", "#1e293b");
      rect.setAttribute("stroke-width", 1.5);
      svg.appendChild(rect);

      // Draw text
      const text1 = document.createElementNS(svgNS, "text");
      text1.setAttribute("x", x);
      text1.setAttribute("y", y - 40);
      text1.setAttribute("text-anchor", "middle");
      text1.setAttribute("font-weight", "bold");
      text1.setAttribute("font-size", "24");
      text1.setAttribute("fill", "#000000");
      text1.setAttribute("font-family", "Arial, sans-serif");
      text1.style.textShadow = "0 0 2px white";
      text1.textContent = globalIndex === 0 ? "Victim Account" : (globalIndex === path.length - 1 ? `Layer: ${node.data.layer - 2 || "N/A"}` : `Layer: ${node.data.layer - 2 || "N/A"}`);
      svg.appendChild(text1);

      const accText = document.createElementNS(svgNS, "text");
      accText.setAttribute("x", x);
      accText.setAttribute("y", globalIndex === 0 ? y : y - 6);
      accText.setAttribute("text-anchor", "middle");
      accText.setAttribute("font-size", "20");
      accText.setAttribute("fill", "#000000");
      accText.setAttribute("font-family", "Arial, sans-serif");
      accText.style.textShadow = "0 0 2px white";
      accText.textContent = `Account No: ${node.data.name || "N/A"}`;
      svg.appendChild(accText);

      const bankText = document.createElementNS(svgNS, "text");
      bankText.setAttribute("x", x);
      bankText.setAttribute("y", bankBaseY);
      bankText.setAttribute("text-anchor", "middle");
      bankText.setAttribute("font-size", "20");
      bankText.setAttribute("fill", "#000000");
      bankText.setAttribute("font-family", "Arial, sans-serif");
      bankText.style.textShadow = "0 0 2px white";

      lines.forEach((line, index) => {
        const tspan = document.createElementNS(svgNS, "tspan");
        tspan.setAttribute("x", x);
        tspan.setAttribute("dy", index === 0 ? "0" : "1.35em");
        tspan.textContent = index === 0 ? `Bank : ${line}` : line;
        bankText.appendChild(tspan);
      });

      svg.appendChild(bankText);

      if (globalIndex === path.length - 1) {
        // Add IFSC code info for Hold Transaction node
        const ifscText = document.createElementNS(svgNS, "text");
        ifscText.setAttribute("x", x);
        ifscText.setAttribute("y", nextY);
        ifscText.setAttribute("text-anchor", "middle");
        ifscText.setAttribute("font-size", "20");
        ifscText.setAttribute("fill", "#000000");
        ifscText.setAttribute("font-family", "Arial, sans-serif");
        ifscText.style.textShadow = "0 0 2px white";
        ifscText.textContent = `IFSC Code: ${node.data.ifsc || "N/A"}`;
        svg.appendChild(ifscText);

        const amtText = document.createElementNS(svgNS, "text");
        amtText.setAttribute("x", x);
        amtText.setAttribute("y", nextY + singleH + gap);
        amtText.setAttribute("text-anchor", "middle");
        amtText.setAttribute("font-size", "20");
        amtText.setAttribute("fill", "#000000");
        amtText.setAttribute("font-family", "Arial, sans-serif");
        amtText.style.textShadow = "0 0 2px white";
        amtText.textContent = `Transacted Amount: ₹${node.data.amt || "0.0"}`;
        svg.appendChild(amtText);

        const txStartY = nextY + singleH * 2 + gap * 2;
        const txHeight = addMultilineText(svg, x, txStartY, `Transaction ID: ${node.data.txid || "N/A"}`, 18);

        const disputedVal = (node.data.disputed && node.data.disputed !== "None") ? node.data.disputed : "0.0";
        const dispY = txStartY + txHeight + gap;
        const dispText = document.createElementNS(svgNS, "text");
        dispText.setAttribute("x", x);
        dispText.setAttribute("y", dispY);
        dispText.setAttribute("text-anchor", "middle");
        dispText.setAttribute("font-size", "20");
        dispText.setAttribute("fill", "#000000");
        dispText.setAttribute("font-family", "Arial, sans-serif");
        dispText.style.textShadow = "0 0 2px white";
        dispText.textContent = `Disputed Amount: ₹${disputedVal}`;
        svg.appendChild(dispText);

        const holdInfo = node.data.hold_info;
        if (holdInfo && holdInfo.amount) {
          const holdText = document.createElementNS(svgNS, "text");
          holdText.setAttribute("x", x);
          holdText.setAttribute("y", dispY + singleH + gap);
          holdText.setAttribute("text-anchor", "middle");
          holdText.setAttribute("font-size", "20");
          holdText.setAttribute("fill", "#000000");
          holdText.setAttribute("font-family", "Arial, sans-serif");
          holdText.style.textShadow = "0 0 2px white";
          holdText.textContent = `Put-On hold Amount: ₹${holdInfo.amount || "0.0"}`;
      svg.appendChild(holdText);
    }
  } else if (globalIndex > 0) {
        // Add IFSC code info for intermediate nodes
        const ifscText = document.createElementNS(svgNS, "text");
        ifscText.setAttribute("x", x);
        ifscText.setAttribute("y", nextY);
        ifscText.setAttribute("text-anchor", "middle");
        ifscText.setAttribute("font-size", "20");
        ifscText.setAttribute("fill", "#000000");
        ifscText.setAttribute("font-family", "Arial, sans-serif");
        ifscText.style.textShadow = "0 0 2px white";
        ifscText.textContent = `IFSC: ${node.data.ifsc || "N/A"}`;
        svg.appendChild(ifscText);

        const amtText = document.createElementNS(svgNS, "text");
        amtText.setAttribute("x", x);
        amtText.setAttribute("y", nextY + singleH + gap);
        amtText.setAttribute("text-anchor", "middle");
        amtText.setAttribute("font-size", "20");
        amtText.setAttribute("fill", "#000000");
        amtText.setAttribute("font-family", "Arial, sans-serif");
        amtText.style.textShadow = "0 0 2px white";
        amtText.textContent = `Transacted Amt: ₹${node.data.amt || "0.0"}`;
      svg.appendChild(amtText);

        const txStartY = nextY + singleH * 2 + gap * 2;
        const txHeight = addMultilineText(svg, x, txStartY, `Transaction ID: ${node.data.txid || "N/A"}`, 18);

        const disputedVal = (node.data.disputed && node.data.disputed !== "None") ? node.data.disputed : "0.0";
        const dispY = txStartY + txHeight + gap;
        const dispText = document.createElementNS(svgNS, "text");
        dispText.setAttribute("x", x);
        dispText.setAttribute("y", dispY);
        dispText.setAttribute("text-anchor", "middle");
        dispText.setAttribute("font-size", "20");
        dispText.setAttribute("fill", "#000000");
        dispText.setAttribute("font-family", "Arial, sans-serif");
        dispText.style.textShadow = "0 0 2px white";
        dispText.textContent = `Disputed Amt: ₹${disputedVal}`;
        svg.appendChild(dispText);

    }

    // Draw line to next node if not last in chunk
      if (i < chunk.length - 1) {
        const line = document.createElementNS(svgNS, "line");
        line.setAttribute("x1", x);
        line.setAttribute("y1", rectY + dynamicBoxHeight);
        line.setAttribute("x2", x);
        line.setAttribute("y2", y + verticalSpacing - (paddingBox)); // connect from bottom of current box to next
        line.setAttribute("stroke", "#888");
        line.setAttribute("stroke-width", 2);
        svg.appendChild(line);
      }
    }

    return svg;
  }

  // Generate images for each chunk
  const promises = chunks.map((chunk, pageIndex) => {
    const startIndex = pageIndex * nodesPerPage;
    const svg = generateSVG(chunk, startIndex);
    const serializer = new XMLSerializer();
    const svgString = serializer.serializeToString(svg);
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = svg.getAttribute("height");
    const ctx = canvas.getContext("2d");
    const img = new Image();
    const svgBlob = new Blob([svgString], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(svgBlob);

    return new Promise((resolve) => {
      img.onload = function () {
        ctx.drawImage(img, 0, 0);
        URL.revokeObjectURL(url);
        const imgData = canvas.toDataURL("image/png");
        resolve(imgData);
      };
      img.src = url;
    });
  });

  Promise.all(promises).then((images) => {
    const content = [
      { text: "\nPut - On Hold Transaction", style: "header", alignment: "center" },
      { text: `Acknowledgement No: ${ackNo}\n\n`, alignment: "center" },
    ];

    images.forEach((imgData, index) => {
      if (index > 0) {
        content.push({ text: `Continuation Page ${index + 1}`, style: "subheader", alignment: "center", pageBreak: 'before' });
      }
      const aspectRatio = width / parseInt(chunks[index][0] ? generateSVG(chunks[index], index * nodesPerPage).getAttribute("height") : 400);
      const pdfHeight = pdfWidth / aspectRatio;
      content.push({
        image: imgData,
        width: pdfWidth,
        height: pdfHeight,
        alignment: "center",
      });
      // Add continuation line if not the last page
      if (index < images.length - 1) {
        content.push({
          canvas: [
            {
              type: 'line',
              x1: 0,
              y1: 10,
              x2: pdfWidth,
              y2: 10,
              lineWidth: 2,
              lineColor: '#888'
            }
          ],
          margin: [0, 20, 0, 20]
        });
      }
    });

    const docDefinition = {
      pageSize: "A4",
      pageOrientation: "portrait",
      content: content,
      styles: {
        header: { fontSize: 16, bold: true, margin: [0, 0, 0, 10] },
        subheader: { fontSize: 14, bold: true, margin: [0, 20, 0, 10] },
      },
    };

    pdfMake.createPdf(docDefinition).download(`HoldTransaction_${ackNo}.pdf`);
  }).catch(() => {
    alert("Failed to generate PDF.");
  });
}
