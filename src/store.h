#pragma once
#include <QJsonObject>
#include <QString>
#include <sys/types.h>

// The helper always uses /etc/fido2 and uid 0. Tests inject a private directory.
QJsonObject applyRegistration(const QString &directory, uid_t owner, const QString &user, const QJsonObject &request);
