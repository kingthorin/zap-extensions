/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.zaproxy.zap.extension.zest;

import java.util.ArrayList;
import java.util.List;
import javax.swing.JComponent;
import javax.swing.JTree;
import javax.swing.TransferHandler;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreePath;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.zaproxy.addon.pscan.ExtensionPassiveScan2;
import org.zaproxy.zap.extension.script.ScriptNode;
import org.zaproxy.zest.core.v1.ZestConditional;
import org.zaproxy.zest.core.v1.ZestContainer;
import org.zaproxy.zest.core.v1.ZestScript;
import org.zaproxy.zest.core.v1.ZestStatement;

@SuppressWarnings("serial")
public class ZestTreeTransferHandler extends TransferHandler {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LogManager.getLogger(ZestTreeTransferHandler.class);
    private ExtensionZest extension;

    public ZestTreeTransferHandler(ExtensionZest ext) {
        extension = ext;
    }

    @Override
    public boolean canImport(TransferHandler.TransferSupport support) {
        // Debug logging commented out as it produces loads of messages. Useful if debugging DnD
        // issues of course ;)
        // LOGGER.debug("canImport {}", support.getComponent().getClass().getCanonicalName());

        support.setShowDropLocation(true);

        // Just support one node at a time right now...
        JTree tree = (JTree) support.getComponent();
        if (tree.getSelectionCount() > 1) {
            return false;
        }
        ScriptNode dragNode = (ScriptNode) tree.getSelectionPath().getLastPathComponent();
        Object uo = dragNode.getUserObject();
        if (!(uo instanceof ZestElementWrapper)) {
            // Can only drag elements
            return false;
        }
        ZestElementWrapper dragZew = (ZestElementWrapper) uo;
        if (dragZew.getElement() instanceof ZestScript) {
            // Never let scripts be dragged
            return false;
        } else if (!(dragZew.getElement() instanceof ZestStatement)) {
            // Dont support other elements yet
            // LOGGER.debug("canImport cant drag to a non ZestStatement {}",
            // dragZew.getElement().getClass().getCanonicalName());
            return false;
        } else if (dragZew.getShadowLevel() > 0) {
            // Only allow the non shadow nodes to be dragged (i.e. not THEN and ELSE)
            return false;
        }

        // Get drop location info.
        JTree.DropLocation dl = (JTree.DropLocation) support.getDropLocation();
        int childIndex = dl.getChildIndex();
        TreePath dest = dl.getPath();
        ScriptNode parent = (ScriptNode) dest.getLastPathComponent();
        if (parent.getUserObject() == null) {
            // LOGGER.debug("canImport cant paste to a null user object {}", parent.toString());
            return false;
        } else if (parent.getUserObject() instanceof ZestScriptWrapper) {
            // Can always paste into scripts, more checks later
        } else if (!(parent.getUserObject() instanceof ZestElementWrapper)) {
            // LOGGER.debug("canImport cant paste to a node of class {}",
            // parent.getUserObject().getClass().getCanonicalName());
            return false;
        } else {
            ZestElementWrapper dropZew = (ZestElementWrapper) parent.getUserObject();
            if (dropZew == null || !(dropZew.getElement() instanceof ZestContainer)) {
                // Dont support other elements yet
                // LOGGER.debug("canImport cant paste to a non ZestContainer {}",
                // dropZew.getElement().getClass().getCanonicalName());
                return false;
            } else if (dropZew.getElement() instanceof ZestConditional
                    && dropZew.getShadowLevel() == 0) {
                // LOGGER.debug("canImport cant paste to an IF statement");
                return false;
            }
        }
        // Check we're not adding non safe statements into passive scripts
        ZestStatement dragStmt = (ZestStatement) dragZew.getElement();
        ZestScriptWrapper sw = extension.getZestTreeModel().getScriptWrapper(parent);
        if (sw == null) {
            return false;
        } else if (ExtensionPassiveScan2.SCRIPT_TYPE_PASSIVE.equals(sw.getTypeName())
                && !isSafe(dragStmt)) {
            // LOGGER.debug("canImport cant paste unsafe stmts into passive script");
            return false;
        }

        // Configure for drop mode.
        if (childIndex >= 0 && childIndex < parent.getChildCount()) {
            // prevent drop between shadow nodes
            ScriptNode nextSibling = (ScriptNode) parent.getChildAt(childIndex);
            if (nextSibling != null) {
                // LOGGER.debug("canImport nextSibling is {}", nextSibling.getNodeName());
                ZestElementWrapper sibZew = (ZestElementWrapper) nextSibling.getUserObject();
                if (sibZew.getShadowLevel() > 0) {
                    // LOGGER.debug("canImport cant paste before shadow node");
                    return false;
                }
            }
        }
        if (parent == dragNode.getParent()
                && childIndex == dragNode.getParent().getIndex(dragNode)) {
            // LOGGER.debug("canImport cant paste into the same location");
            return false;
        }

        return true;
    }

    private boolean isSafe(ZestStatement stmt) {
        if (!stmt.isPassive()) {
            return false;
        }
        if (stmt instanceof ZestContainer) {
            for (ZestStatement child : ((ZestConditional) stmt).getChildren()) {
                if (!isSafe(child)) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public int getSourceActions(JComponent c) {
        LOGGER.debug("getSourceActions {}", c.getClass().getCanonicalName());
        return TransferHandler.COPY_OR_MOVE;
    }

    @Override
    public boolean importData(TransferHandler.TransferSupport support) {
        LOGGER.debug("importData {}", support.getComponent().getClass().getCanonicalName());

        if (!support.isDrop()) {
            return false;
        }

        JTree tree = (JTree) support.getComponent();

        ScriptNode dragNode = (ScriptNode) tree.getSelectionPath().getLastPathComponent();

        // Get drop location info.
        JTree.DropLocation dl = (JTree.DropLocation) support.getDropLocation();
        int childIndex = dl.getChildIndex();
        TreePath dest = dl.getPath();
        DefaultMutableTreeNode parent = (DefaultMutableTreeNode) dest.getLastPathComponent();
        boolean cut = (support.getDropAction() & MOVE) == MOVE;

        if (parent.getUserObject() == null) {
            return false;
        } else if (!(parent.getUserObject() instanceof ZestElementWrapper)
                && !(parent.getUserObject() instanceof ZestScriptWrapper)) {
            return false;
        }

        ScriptNode beforeChild = null;
        ScriptNode afterChild = null;

        if (childIndex >= 0) {
            if (childIndex == parent.getChildCount()) {
                afterChild = (ScriptNode) parent.getChildAt(childIndex - 1);
            } else {
                beforeChild = (ScriptNode) parent.getChildAt(childIndex);
            }
        }

        List<ScriptNode> nodes = new ArrayList<>();
        nodes.add(dragNode);

        extension.pasteToNode((ScriptNode) parent, nodes, cut, beforeChild, afterChild);
        return true;
    }
}
