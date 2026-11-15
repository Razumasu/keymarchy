#pragma once
#include "registry.h"
#include <QJsonArray>
#include <QVariantList>
#include <functional>

enum class Match { Absent, Present, Unknown };
struct AttachedKey { QString path; QString description; QString identity; };
using Probe = std::function<Match(const AttachedKey &, const Key &)>;
QByteArray decodeCredentialHandle(const QByteArray &credential);
// The product name is whatever the USB device claims, so keep it short and printable.
QString sanitizeDescription(const QString &raw);
QJsonObject detectPresence(const QVector<Key> &keys, const QVector<AttachedKey> &devices, const Probe &probe);
QJsonObject scanPresence(const QString &cachedToken = {});
QVariantList applyPresence(const QVariantList &keys, const QJsonObject &result);
