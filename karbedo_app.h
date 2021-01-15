#ifndef KARBEDO_APP_H
#define KARBEDO_APP_H

#include <QApplication>
#include <QEvent>
#include <typeinfo>
#include <QDebug>
#include <parsingexception.h>


/**
 * @class karbedo_app
 * @brief Application with reimplemented notify() method.
 */
class karbedo_app final : public QApplication
{
    Q_OBJECT

public:
    karbedo_app(int &argc, char **argv) : QApplication(argc, argv) {}

    /**
    * @brief Handles some possible Event System exceptions.
    * @param receiver - event receiving object.
    * @param event    - object delivered to the receiver.
    */
    bool notify(QObject *receiver, QEvent *event) override
    {
        try {
            return QApplication::notify(receiver, event);
        } catch (QException &e) {
            qDebug("Exception <%s>: sending event %s to %s <%s> failed",
                e.what(), typeid(*event).name(), qPrintable(receiver->objectName()),
                typeid(*receiver).name());
        } catch (...) {
            qDebug("Exception: sending event %s to %s <%s> failed",
                typeid(*event).name(), qPrintable(receiver->objectName()),
                typeid(*receiver).name());
        }

         return false;
     }
};





#endif // KARBEDO_APP_H
