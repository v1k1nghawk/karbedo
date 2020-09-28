#include <QMetaType> // for connection registeration
#include "mainwindow.h"
#include "karbedo_app.h"


int main(int argc, char *argv[])
{
    karbedo_app app(argc, argv);

    // register before any signal-slot connections
    qRegisterMetaType<guiUpdater>("guiUpdater");
    qRegisterMetaType<user>("user");

    MainWindow w;
    w.setWindowTitle(APP_NAME + " vers" + VERSION_MAJOR + "." + VERSION_MINOR);
    w.setFixedSize(w.size());
    w.show();

    return app.exec();
}
