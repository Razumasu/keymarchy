#include "presence.h"
#include <fido.h>
#include <fido/es256.h>
#include <fido/eddsa.h>
#include <fido/rs256.h>
#include <QFile>
#include <QJsonDocument>
#include <QRandomGenerator>
#include <QScopeGuard>
#include <QSysInfo>
#include <sys/stat.h>

static const unsigned char *bytes(const QByteArray &value) {
    return reinterpret_cast<const unsigned char *>(value.constData());
}
static QByteArray decode(const QByteArray &value) {
    const auto decoded = QByteArray::fromBase64Encoding(value, QByteArray::AbortOnBase64DecodingErrors);
    if (!decoded || decoded.decoded.isEmpty()) throw Failure(appText("Invalid credential encoding."));
    return decoded.decoded;
}
static bool verify(fido_assert_t *assertion, const QList<QByteArray> &fields) {
    auto publicKey = fields.size() == 2 ? QByteArray::fromHex(fields[1]) : decode(fields[1]);
    const auto algorithm = fields.size() == 2 ? QByteArray("es256") : fields[2];
    if (fields.size() == 2 && publicKey.size() == 65 && publicKey[0] == '\x04') publicKey.remove(0, 1);
    if (fido_assert_count(assertion) != 1) return false;
    if (algorithm == "es256") {
        auto *pk = es256_pk_new();
        const auto cleanup = qScopeGuard([&] { es256_pk_free(&pk); });
        return pk && es256_pk_from_ptr(pk, bytes(publicKey), publicKey.size()) == FIDO_OK &&
               fido_assert_verify(assertion, 0, COSE_ES256, pk) == FIDO_OK;
    }
    if (algorithm == "eddsa") {
        auto *pk = eddsa_pk_new();
        const auto cleanup = qScopeGuard([&] { eddsa_pk_free(&pk); });
        return pk && eddsa_pk_from_ptr(pk, bytes(publicKey), publicKey.size()) == FIDO_OK &&
               fido_assert_verify(assertion, 0, COSE_EDDSA, pk) == FIDO_OK;
    }
    if (algorithm == "rs256") {
        auto *pk = rs256_pk_new();
        const auto cleanup = qScopeGuard([&] { rs256_pk_free(&pk); });
        return pk && rs256_pk_from_ptr(pk, bytes(publicKey), publicKey.size()) == FIDO_OK &&
               fido_assert_verify(assertion, 0, COSE_RS256, pk) == FIDO_OK;
    }
    return false;
}
static Match probeDevice(const AttachedKey &device, const Key &key) {
    auto *dev = fido_dev_new();
    auto *assertion = fido_assert_new();
    bool opened = false;
    const auto cleanup = qScopeGuard([&] {
        fido_assert_free(&assertion);
        if (opened) fido_dev_close(dev);
        fido_dev_free(&dev);
    });
    if (!dev || !assertion) return Match::Unknown;
    if (fido_dev_set_timeout(dev, 750) != FIDO_OK ||
        fido_dev_open(dev, QFile::encodeName(device.path).constData()) != FIDO_OK) return Match::Unknown;
    opened = true;
    try {
        const auto fields = key.credential.split(',');
        const auto handle = decode(fields[0]);
        const auto rp = ("pam://" + QSysInfo::machineHostName()).toUtf8();
        quint32 challenge[8];
        QRandomGenerator::system()->fillRange(challenge);
        if (fido_assert_set_rp(assertion, rp.constData()) != FIDO_OK ||
            fido_assert_set_clientdata_hash(assertion, reinterpret_cast<unsigned char *>(challenge), sizeof(challenge)) != FIDO_OK ||
            fido_assert_allow_cred(assertion, bytes(handle), handle.size()) != FIDO_OK ||
            fido_assert_set_up(assertion, FIDO_OPT_FALSE) != FIDO_OK ||
            fido_assert_set_uv(assertion, FIDO_OPT_OMIT) != FIDO_OK) return Match::Unknown;
        const int result = fido_dev_get_assert(dev, assertion, nullptr);
        // U2F check-only returns this status for a recognized handle; no touch is requested.
        if (!fido_dev_is_fido2(dev) && result == FIDO_ERR_USER_PRESENCE_REQUIRED) return Match::Present;
        if (result == FIDO_ERR_NO_CREDENTIALS) return Match::Absent;
        if (result != FIDO_OK) return Match::Unknown;
        return verify(assertion, fields) ? Match::Present : Match::Unknown;
    } catch (const std::exception &) { return Match::Unknown; }
}
QJsonObject detectPresence(const QVector<Key> &keys, const QVector<AttachedKey> &devices, const Probe &probe) {
    QJsonArray registrations;
    for (const auto &key : keys) {
        bool uncertain = false;
        QJsonArray matches;
        for (const auto &device : devices) {
            const auto match = probe(device, key);
            if (match == Match::Present) matches.append(device.description);
            if (match == Match::Unknown) uncertain = true;
        }
        registrations.append(QJsonObject{{"id", key.id}, {"connection", !matches.isEmpty() ? "connected" : uncertain ? "unknown" : "disconnected"}, {"devices", matches}});
    }
    return {{"keys",registrations},{"deviceCount",devices.size()}};
}
QJsonObject scanPresence(const QString &cachedToken) {
    const auto configuration = checkConfiguration();
    if (!configuration.isEmpty()) throw Failure(configuration);
    const Registry registry(readFile("/etc/fido2/fido2"), currentUser());
    fido_init(0);
    constexpr size_t maximum = 64;
    auto *list = fido_dev_info_new(maximum);
    if (!list) throw Failure(appText("Cannot allocate device discovery."));
    const auto cleanup = qScopeGuard([&] { fido_dev_info_free(&list, maximum); });
    size_t count = 0;
    if (fido_dev_info_manifest(list, maximum, &count) != FIDO_OK || count == maximum)
        throw Failure(appText("Cannot enumerate all security keys."));
    QVector<AttachedKey> devices;
    QJsonArray identities;
    for (size_t i = 0; i < count; ++i) {
        const auto *info = fido_dev_info_ptr(list, i);
        const auto path = QString::fromLocal8Bit(fido_dev_info_path(info));
        auto description = QString::fromUtf8(fido_dev_info_product_string(info));
        if (description.isEmpty()) description = appText("Security key");
        struct stat st{};
        if (stat(QFile::encodeName(path).constData(), &st) != 0) throw Failure(appText("A security key changed during detection. Retrying…"));
        // Include the device node's generation so reusing /dev/hidrawN after a swap invalidates the cache.
        const auto identity = QString("%1:%2:%3:%4:%5").arg(path).arg(qulonglong(st.st_ino)).arg(qulonglong(st.st_rdev)).arg(qlonglong(st.st_ctim.tv_sec)).arg(qlonglong(st.st_ctim.tv_nsec));
        identities.append(identity);
        devices.append({path,description,identity});
    }
    const auto token = Registry::fingerprint(registry.revision().toLatin1() + QSysInfo::machineHostName().toUtf8() + QJsonDocument(identities).toJson(QJsonDocument::Compact));
    if (token == cachedToken) return {{"unchanged",true},{"token",token},{"revision",registry.revision()}};
    auto result = detectPresence(registry.keys(), devices, probeDevice);
    bool uncertain = false;
    for (const auto &row : result.value("keys").toArray()) uncertain |= row.toObject().value("connection") == "unknown";
    // Retry temporary access/transport errors instead of caching them as absence.
    result.insert("token", uncertain ? QString() : token);
    result.insert("revision",registry.revision());
    return result;
}
QVariantList applyPresence(const QVariantList &keys, const QJsonObject &result) {
    QHash<QString,QJsonObject> states;
    for (const auto &value : result.value("keys").toArray()) states.insert(value.toObject().value("id").toString(),value.toObject());
    QVariantList updated;
    for (const auto &value : keys) {
        auto row = value.toMap();
        const auto state = states.value(row.value("id").toString());
        row.insert("connection",state.value("connection").toString("unknown"));
        row.insert("devices",state.value("devices").toArray().toVariantList());
        updated.append(row);
    }
    return updated;
}
