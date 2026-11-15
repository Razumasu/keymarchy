#pragma once
#include <QByteArray>
#include <QString>
#include <functional>

struct Enrollment {
    QString lister = "/usr/bin/fido2-token";
    QString enroller = "/usr/bin/pamu2fcfg";
    int cancelFd = 0;             // end of file here cancels a pending enrollment
    int timeout = 30000;          // milliseconds to wait for the touch
    std::function<void()> ready;  // called once the key is waiting for a touch
};
// Creates a credential on the only connected key and returns its registration,
// as pamu2fcfg prints it without the user name. Tests inject the two programs.
QByteArray enrollCredential(const QString &user, const Enrollment &options = {});
