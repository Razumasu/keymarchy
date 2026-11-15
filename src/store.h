#pragma once
#include <QByteArray>
#include <QJsonObject>
#include <QString>
#include <functional>
#include <sys/types.h>

// Returns the registration created by enrolling the connected key.
using Enroll = std::function<QByteArray()>;

// The helper always uses /etc/fido2 and uid 0. Tests inject a private directory.
// An added registration only ever comes from `enroll`, never from the request.
QJsonObject applyRegistration(const QString &directory, uid_t owner, const QString &user,
                              const QJsonObject &request, const Enroll &enroll = {});
