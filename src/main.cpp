#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QIcon>
#include <QTextStream>
#include <QJsonDocument>
#include <QJsonArray>
#include <QTimer>
#include <QSaveFile>
#include <QDir>
#include "backend.h"
#include "presence.h"
#include "registry.h"
#include "theme.h"
#include "translator.h"

int main(int argc, char **argv) {
    QStringList args;
    for (int i = 1; i < argc; ++i) args << QString::fromLocal8Bit(argv[i]);
    if (args == QStringList{"--helper"}) { QCoreApplication app(argc,argv); return runHelper(); }
    if (args.value(0) == "--scan" && args.size() <= 2) {
        QCoreApplication app(argc,argv);
        try { QTextStream(stdout) << QJsonDocument(scanPresence(args.value(1))).toJson(QJsonDocument::Compact) << '\n'; return 0; }
        catch (const std::exception &e) { QTextStream(stderr) << e.what() << '\n'; return 1; }
    }
    const bool gui = args.isEmpty() || args.first() == "open" || args.first() == "--preview";
    if (!gui) { qputenv("QT_QPA_PLATFORM", "offscreen"); qputenv("QT_QPA_PLATFORMTHEME", "basic"); }
    QGuiApplication app(argc,argv);
    app.setApplicationName("keymarchy"); app.setApplicationVersion("0.3.1");
    app.setDesktopFileName("keymarchy"); app.setWindowIcon(QIcon::fromTheme("keymarchy"));
    QQuickStyle::setStyle("Material");
    Translator translator; app.installTranslator(&translator);
    if (args == QStringList{"skill","install"}) {
        const QString dir = QDir::homePath() + "/.agents/skills/keymarchy";
        try {
            if (!QDir().mkpath(dir)) throw Failure("Cannot create skill directory.");
            QSaveFile f(dir + "/SKILL.md"); const auto bytes = readFile(":/SKILL.md");
            if (!f.open(QIODevice::WriteOnly) || f.write(bytes) != bytes.size() || !f.commit()) throw Failure("Cannot install skill.");
            QTextStream(stdout) << "Installed " << dir << "/SKILL.md\n"; return 0;
        } catch (const std::exception &e) { QTextStream(stderr) << e.what() << '\n'; return 1; }
    }
    if (args.contains("--help") || args.contains("-h")) {
        QTextStream(stdout) << "Keymarchy 0.3.1 — security keys for Omarchy\n"
            "  keymarchy open\n  keymarchy list [--json]\n  keymarchy add NAME [--json]\n"
            "  keymarchy rename ID NAME [--json]\n  keymarchy remove ID --yes [--json]\n"
            "  keymarchy skill install\n\nUse full registration IDs from list --json. Add/remove require system authentication.\n";
        return 0;
    }
    const bool preview = args.value(0) == "--preview";
    Backend backend(preview);
    if (!gui) {
        const bool json = args.removeAll("--json") > 0;
        const auto command = args.value(0);
        if (command == "list" && args.size() == 1) {
            auto keys = backend.keys();
            QString detectionError;
            if (backend.problem().isEmpty()) {
                try { keys = applyPresence(keys, scanPresence()); }
                catch (const std::exception &e) { detectionError = QString::fromUtf8(e.what()); keys = applyPresence(keys, {}); }
            }
            if (json) QTextStream(stdout) << QJsonDocument(QJsonObject{{"keys",QJsonArray::fromVariantList(keys)},{"problem",backend.problem()},{"detectionError",detectionError}}).toJson();
            else for (const auto &item : keys) { const auto key=item.toMap(); QTextStream(stdout) << key.value("id").toString() << "  " << key.value("name").toString() << "  [" << key.value("connection").toString() << "]" << '\n'; }
            if (!backend.problem().isEmpty()) { QTextStream(stderr) << backend.problem() << '\n'; return 1; }
            if (!detectionError.isEmpty()) { QTextStream(stderr) << detectionError << '\n'; return 1; }
            return 0;
        }
        QObject::connect(&backend,&Backend::completed,&app,[&](bool success) {
            if (json) QTextStream(stdout) << QJsonDocument(QJsonObject{{"ok",success},{"message",backend.message()}}).toJson(QJsonDocument::Compact) << '\n';
            else QTextStream(success ? stdout : stderr) << backend.message() << '\n';
            if (json && !success) QTextStream(stderr) << backend.message() << '\n';
            app.exit(success ? 0 : 1);
        });
        QObject::connect(&backend,&Backend::changed,&app,[&] { if (backend.busy()) QTextStream(stderr) << backend.message() << '\n'; });
        QTimer::singleShot(0,&app,[&] {
            if (command == "add" && args.size() == 2) backend.add(args[1]);
            else if (command == "rename" && args.size() == 3) backend.rename(args[1],args[2]);
            else if (command == "remove" && args.size() == 3 && args[2] == "--yes") backend.remove(args[1]);
            else { QTextStream(stderr) << "Invalid arguments. Run keymarchy --help. Removal requires --yes.\n"; app.exit(1); }
        });
        return app.exec();
    }
    if (!preview) backend.startMonitoring();
    Theme theme(preview ? "/nonexistent-keymarchy-preview" : QString());
    QQmlApplicationEngine engine;
    QObject::connect(&translator,&Translator::changed,&engine,&QQmlEngine::retranslate);
    QObject::connect(&translator,&Translator::changed,&backend,&Backend::refresh);
    engine.rootContext()->setContextProperty("backend",&backend);
    engine.rootContext()->setContextProperty("theme",&theme);
    engine.rootContext()->setContextProperty("translator",&translator);
    engine.load(QUrl("qrc:/Main.qml"));
    if (engine.rootObjects().isEmpty()) return 1;
    if (preview && args.size() == 2) {
        QTimer::singleShot(1000,&app,[&] {
            auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().first());
            app.exit(window && window->grabWindow().save(args[1]) ? 0 : 1);
        });
    }
    return app.exec();
}
