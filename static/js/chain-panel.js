/*
 * 漏洞链面板组件
 * 依赖: jQuery
 *
 * 用法:
 *   在结果行末尾加一个按钮:
 *     <button class="btn btn-xs btn-chain" data-vul-id="{{ taskresult.id }}" onclick="toggleChainPanel(this)">
 *       <i class="fa fa-sitemap"></i>
 *     </button>
 *
 *   在表格后面放一个隐藏面板:
 *     <div id="chainPanel" class="km-chain-panel" style="display:none">
 *       <div class="km-chain-sidebar" id="chainSidebar"></div>
 *       <div class="km-chain-code" id="chainCode"></div>
 *     </div>
 *
 *   Data passed via Django template rendering into chainDataMap.
 *     <script>var chainDataMap = {{ chain_data_json|safe }};</script>
 */
var chainPanelVisible = false;
var chainPanelVulId = null;
var chainDataMap = chainDataMap || {};

// 节点类型图标和颜色
var NODE_STYLES = {
    'source':  { icon: 'fa-crosshairs', color: '#e74c3c', label: '数据入口' },
    'sink':    { icon: 'fa-bomb',       color: '#e67e22', label: '危险函数' },
    'NewScan': { icon: 'fa-search',     color: '#3498db', label: '匹配代码' },
};
var DEFAULT_NODE_STYLE = { icon: 'fa-circle', color: '#95a5a6', label: '传播节点' };

function getNodeStyle(type) {
    return NODE_STYLES[type] || DEFAULT_NODE_STYLE;
}

function toggleChainPanel(btn) {
    var vulId = btn.getAttribute('data-vul-id');
    var panel = document.getElementById('chainPanel');
    if (!panel) return;

    if (chainPanelVisible && chainPanelVulId == vulId) {
        // 关闭
        panel.style.display = 'none';
        chainPanelVisible = false;
        chainPanelVulId = null;
        // 取消所有行高亮
        document.querySelectorAll('.km-chain-row-active').forEach(function(el) {
            el.classList.remove('km-chain-row-active');
        });
        return;
    }

    chainPanelVulId = vulId;
    chainPanelVisible = true;
    panel.style.display = 'flex';

    // 高亮当前行
    document.querySelectorAll('.km-chain-row-active').forEach(function(el) {
        el.classList.remove('km-chain-row-active');
    });
    var row = btn.closest('tr');
    if (row) row.classList.add('km-chain-row-active');

    // 渲染链
    renderChain(vulId);
}

function renderChain(vulId) {
    var nodes = chainDataMap[vulId];
    var sidebar = document.getElementById('chainSidebar');
    var codeArea = document.getElementById('chainCode');
    if (!sidebar || !codeArea) return;

    if (!nodes || nodes.length === 0) {
        sidebar.innerHTML = '<div class="km-chain-empty">暂无链数据</div>';
        codeArea.innerHTML = '<div class="km-chain-empty">选择左侧节点查看代码</div>';
        return;
    }

    // 渲染左侧节点链
    var html = '<div class="km-chain-title">漏洞传播链</div>';
    html += '<div class="km-chain-nodes">';
    for (var i = 0; i < nodes.length; i++) {
        var node = nodes[i];
        var style = getNodeStyle(node.type);
        var relPath = node.path || '';
        var isActive = (i === nodes.length - 1); // 默认选中最后一个节点(sink)

        html += '<div class="km-chain-node' + (isActive ? ' km-chain-node-active' : '') + '" data-idx="' + i + '" onclick="selectChainNode(' + i + ')">';
        html += '  <div class="km-chain-node-icon" style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i></div>';
        html += '  <div class="km-chain-node-info">';
        html += '    <div class="km-chain-node-type" style="color:' + style.color + '">' + (style.label || node.type) + '</div>';
        html += '    <div class="km-chain-node-content" title="' + escapeHtml(node.content) + '">' + escapeHtml(node.content) + '</div>';
        if (relPath && node.lineno) {
            html += '    <div class="km-chain-node-loc">' + escapeHtml(relPath.split('/').pop()) + ':' + node.lineno + '</div>';
        }
        html += '  </div>';
        html += '</div>';

        // 连线(非最后一个节点)
        if (i < nodes.length - 1) {
            html += '<div class="km-chain-connector"><div class="km-chain-connector-line"></div></div>';
        }
    }
    html += '</div>';
    sidebar.innerHTML = html;

    // 默认选中最后一个节点
    selectChainNode(nodes.length - 1);
}

function selectChainNode(idx) {
    var nodes = chainDataMap[chainPanelVulId];
    if (!nodes || !nodes[idx]) return;

    var node = nodes[idx];

    // 更新左侧高亮
    document.querySelectorAll('.km-chain-node').forEach(function(el) {
        el.classList.remove('km-chain-node-active');
    });
    var activeNode = document.querySelector('.km-chain-node[data-idx="' + idx + '"]');
    if (activeNode) activeNode.classList.add('km-chain-node-active');

    // 右侧显示代码
    var codeArea = document.getElementById('chainCode');
    if (!codeArea) return;

    if (node.source) {
        var lines = node.source.split('\n');
        var targetLineno = parseInt(node.lineno) || 0;
        var html = '<div class="km-chain-code-header">';
        var style = getNodeStyle(node.type);
        html += '<span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span>';
        if (node.path) {
            html += ' <span class="km-chain-code-path">' + escapeHtml(node.path.split('/').pop()) + ':' + node.lineno + '</span>';
        }
        html += '</div>';
        html += '<div class="km-chain-code-body">';
        html += '<table class="km-chain-code-table"><tbody>';
        for (var i = 0; i < lines.length; i++) {
            var lineNum = 0;
            // node_source 格式: "  12: \tcode\n  13: \tcode"
            var match = lines[i].match(/^(\s*)(\d+):/);
            if (match) {
                lineNum = parseInt(match[2]);
            }
            var isTarget = (lineNum === targetLineno);
            var lineContent = lines[i].replace(/^\s*\d+:\s*/, '');
            html += '<tr class="' + (isTarget ? 'km-chain-line-highlight' : '') + '">';
            html += '<td class="km-chain-lineno">' + (lineNum || '') + '</td>';
            html += '<td class="km-chain-code-line">' + escapeHtml(lineContent) + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        codeArea.innerHTML = html;
    } else {
        var style = getNodeStyle(node.type);
        codeArea.innerHTML = '<div class="km-chain-code-header"><span style="color:' + style.color + '"><i class="fa ' + style.icon + '"></i> ' + (style.label || node.type) + '</span></div>'
            + '<div class="km-chain-code-body"><pre>' + escapeHtml(node.content || '(无代码)') + '</pre></div>';
    }
}

function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
