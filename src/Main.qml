import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import QtQuick.Layouts

ApplicationWindow {
    id: win
    width: 820; height: 670
    minimumWidth: 660; minimumHeight: 580
    visible: true
    title: "Keykeep"
    color: "#101214"
    Material.theme: Material.Dark
    Material.accent: theme.accent
    Material.roundedScale: theme.radius
    property var selected: list.currentIndex >= 0 && list.currentIndex < backend.keys.length ? backend.keys[list.currentIndex] : null
    property bool editing: nameDialog.visible || removeDialog.visible || helpDialog.visible
    onClosing: function(close) { if (backend.busy) { close.accepted = false; busyDialog.open() } }
    Shortcut { sequence: "?"; context: Qt.ApplicationShortcut; enabled: !win.editing; onActivated: helpDialog.open() }
    Shortcut { sequence: "Q"; context: Qt.ApplicationShortcut; enabled: !win.editing; onActivated: win.close() }
    Shortcut { sequence: "Space"; context: Qt.ApplicationShortcut; enabled: !win.editing && !backend.busy && !backend.problem; onActivated: win.openName(false) }
    Shortcut { sequence: "Ctrl+N"; context: Qt.ApplicationShortcut; enabled: !win.editing && !backend.busy && !backend.problem; onActivated: win.openName(false) }
    Shortcut { sequence: "F2"; context: Qt.ApplicationShortcut; enabled: !win.editing && !backend.busy && win.selected !== null; onActivated: win.openName(true) }
    Shortcut { sequence: "Delete"; context: Qt.ApplicationShortcut; enabled: !win.editing && !backend.busy && !backend.problem && win.selected !== null; onActivated: win.openRemove() }
    Shortcut { sequence: "Ctrl+R"; context: Qt.ApplicationShortcut; enabled: !win.editing && !backend.busy; onActivated: backend.refresh() }
    function openName(rename) {
        nameDialog.renaming = rename
        nameDialog.keyId = rename ? win.selected.id : ""
        nameField.text = rename ? win.selected.name : ""
        nameDialog.open()
        nameField.forceActiveFocus()
        nameField.selectAll()
    }
    function openRemove() {
        removeDialog.keyId = win.selected.id
        removeDialog.keyName = win.selected.name
        removeDialog.open()
    }
    Item {
        anchors.fill: parent
        LayoutMirroring.enabled: Qt.application.layoutDirection === Qt.RightToLeft
        LayoutMirroring.childrenInherit: true
        ColumnLayout {
            anchors.fill: parent; anchors.margins: 32; spacing: 20
            RowLayout {
                Layout.fillWidth: true
                Rectangle {
                    width: 44; height: 44; radius: Math.min(8, theme.radius); color: theme.accent
                    Text { anchors.centerIn: parent; text: "K"; font.pixelSize: 26; font.bold: true; color: theme.accentForeground }
                }
                ColumnLayout {
                    spacing: 2
                    Label { text: "Keykeep"; font.pixelSize: 26; font.bold: true }
                    Label { text: qsTr("Security keys for Omarchy"); color: "#a3aaa8" }
                }
                Item { Layout.fillWidth: true }
                ToolButton { text: "?"; Accessible.name: qsTr("Keyboard shortcuts"); onClicked: helpDialog.open() }
            }
            Rectangle { Layout.fillWidth: true; height: 1; color: "#303638" }
            RowLayout {
                Layout.fillWidth: true
                ColumnLayout {
                    spacing: 5
                    Label { text: qsTr("Your security keys"); font.pixelSize: 21; font.bold: true }
                    Label { text: { translator.language; return qsTr("%n registered key(s)", "", backend.keys.length) } color: "#a3aaa8" }
                }
                Item { Layout.fillWidth: true }
                Button { text: qsTr("Refresh"); enabled: !backend.busy; onClicked: backend.refresh() }
                Button { objectName: "addButton"; text: qsTr("Add key"); highlighted: true; background: Rectangle { color: parent.enabled ? theme.accent : "#454b48"; radius: Math.min(6, theme.radius) } contentItem: Text { text: parent.text; font: parent.font; color: theme.accentForeground; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter } enabled: !backend.busy && !backend.problem; onClicked: win.openName(false) }
            }
            Label {
                Layout.fillWidth: true; visible: !!backend.problem
                text: backend.problem; wrapMode: Text.WordWrap; color: "#f3b794"
                Accessible.role: Accessible.AlertMessage
            }
            Label {
                Layout.fillWidth: true; wrapMode: Text.WordWrap
                text: backend.connectionMessage; color: "#a3aaa8"; font.pixelSize: 12
                visible: text.length > 0
            }
            ListView {
                id: list; objectName: "keyList"
                Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 8
                model: backend.keys; currentIndex: -1
                keyNavigationEnabled: true
                ScrollBar.vertical: ScrollBar {}
                delegate: Rectangle {
                    required property var modelData
                    required property int index
                    width: list.width; height: 78; radius: Math.min(8, theme.radius)
                    color: ListView.isCurrentItem || modelData.connection === "connected" ? "#252e2b" : "#1a1e20"
                    border.color: ListView.isCurrentItem ? theme.accent : "#303638"
                    MouseArea { anchors.fill: parent; onClicked: { list.currentIndex = index; list.forceActiveFocus() } }
                    RowLayout {
                        anchors.fill: parent; anchors.margins: 16; spacing: 14
                        Rectangle { width: 10; height: 10; radius: 5; color: modelData.connection === "connected" ? theme.accent : "#64716a" }
                        ColumnLayout {
                            Layout.fillWidth: true; spacing: 5
                            Label { text: modelData.name; font.pixelSize: 16; font.bold: true; elide: Text.ElideRight; Layout.fillWidth: true; textFormat: Text.PlainText }
                            RowLayout {
                                Layout.fillWidth: true; spacing: 10
                                Label {
                                    objectName: "connectionBadge"
                                    text: modelData.connection === "connected" ? qsTr("Connected") : modelData.connection === "disconnected" ? qsTr("Not connected") : modelData.connection === "checking" ? qsTr("Checking…") : qsTr("Unable to check")
                                    color: modelData.connection === "connected" ? theme.accent : "#929c98"
                                    font.pixelSize: 12; font.bold: modelData.connection === "connected"
                                }
                                Label { text: modelData.shortId; color: "#929c98"; font.pixelSize: 12; font.family: "monospace"; elide: Text.ElideRight; Layout.fillWidth: true }
                            }
                        }
                        Button { text: qsTr("Rename"); enabled: !backend.busy; onClicked: { list.currentIndex = index; win.openName(true) } }
                        Button { text: qsTr("Remove"); enabled: !backend.busy && !backend.problem; onClicked: { list.currentIndex = index; win.openRemove() } }
                    }
                }
                Label { anchors.centerIn: parent; visible: list.count === 0; text: qsTr("No registered keys"); color: "#a3aaa8" }
            }
            Rectangle {
                Layout.fillWidth: true; implicitHeight: statusRow.implicitHeight + 28
                radius: Math.min(8, theme.radius); color: "#1a1e20"
                RowLayout {
                    id: statusRow; anchors.fill: parent; anchors.margins: 14; spacing: 12
                    BusyIndicator { running: backend.busy; visible: running; implicitWidth: 28; implicitHeight: 28 }
                    Label {
                        Layout.fillWidth: true; wrapMode: Text.WordWrap; textFormat: Text.PlainText
                        text: backend.message || qsTr("Use names like “Everyday” or “Backup” to tell your keys apart.")
                        color: backend.busy ? theme.accent : "#bac2bf"
                    }
                    Button { text: qsTr("Cancel"); visible: backend.busy && backend.phase !== "authorize"; onClicked: backend.cancel() }
                }
            }
            Label {
                Layout.fillWidth: true; wrapMode: Text.WordWrap; font.pixelSize: 12; color: "#929c98"
                text: qsTr("These registrations allow sudo and any other service using Omarchy’s FIDO2 file. Removing one here does not reset the physical key.")
            }
        }
    }
    Dialog {
        id: nameDialog; objectName: "nameDialog"
        property bool renaming: false
        property string keyId: ""
        anchors.centerIn: parent; width: Math.min(480, win.width - 64)
        modal: true; title: renaming ? qsTr("Rename key") : qsTr("Add a security key")
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: { standardButton(Dialog.Ok).text = renaming ? qsTr("Save name") : qsTr("Start enrollment"); standardButton(Dialog.Ok).enabled = nameField.text.trim().length > 0 }
        onAccepted: { if (renaming) backend.rename(keyId, nameField.text); else backend.add(nameField.text) }
        ColumnLayout {
            width: parent.width; spacing: 16
            Label { Layout.fillWidth: true; wrapMode: Text.WordWrap; visible: !nameDialog.renaming; text: qsTr("Connect only the key you want to add. You’ll touch it to enroll, then approve a system prompt to save.") }
            TextField { id: nameField; objectName: "nameField"; Layout.fillWidth: true; placeholderText: qsTr("Key name"); maximumLength: 80; onTextChanged: { if (nameDialog.visible) nameDialog.standardButton(Dialog.Ok).enabled = text.trim().length > 0 } onAccepted: { if (text.trim().length) nameDialog.accept() } }
        }
    }
    Dialog {
        id: removeDialog; objectName: "removeDialog"
        property string keyId: ""
        property string keyName: ""
        anchors.centerIn: parent; width: Math.min(480, win.width - 64)
        modal: true; title: qsTr("Remove this key?")
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: standardButton(Dialog.Ok).text = qsTr("Remove key")
        onAccepted: backend.remove(keyId)
        Label { width: parent.width; wrapMode: Text.WordWrap; textFormat: Text.PlainText
            text: (backend.keys.length === 1 ? qsTr("This is your last registered key. You’ll use your password after removing it.") + "\n\n" : "") + qsTr("Remove “%1” from this computer’s FIDO2 registrations? A backup will be saved.").arg(removeDialog.keyName) }
    }
    Dialog {
        id: helpDialog; anchors.centerIn: parent; width: 410; modal: true
        title: qsTr("Keyboard shortcuts"); standardButtons: Dialog.Close
        Label { text: qsTr("Space / Ctrl+N    Add key\nF2    Rename selected key\nDelete    Remove selected key\nCtrl+R    Refresh\n?    Keyboard shortcuts\nQ    Quit"); lineHeight: 1.6 }
    }
    Dialog {
        id: busyDialog; anchors.centerIn: parent; width: 420; modal: true
        title: qsTr("Operation in progress"); standardButtons: Dialog.Ok
        Label { width: parent.width; wrapMode: Text.WordWrap; text: qsTr("Finish the system prompt or cancel enrollment before closing Keykeep.") }
    }
}
