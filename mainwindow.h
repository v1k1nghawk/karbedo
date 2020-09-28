#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidgetItem>
#include <QFileDialog>
#include <QDir>
#include <QDate>
#include <QStringListModel>
#include <QElapsedTimer>
#include <boost/container/vector.hpp>
#include <general.h>
#include <shadowparsingexception.h>
#include <user.h>
#include <guiupdater.h>

using namespace boost::container;


namespace Ui {
class MainWindow;
}

/**
 * @class MainWindow
 * @brief program's GUI.
 */
class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:

    /**
    * @brief Choose shadow-type file.
    */
    void openFileButton_clicked();

    /**
    * @brief Choose target user from a selected file.
    * @see user
    */
    void on_usersCBox_currentTextChanged();

    /**
    * @brief "STOP" handler, stopActions() caller.
    * @see stopActions()
    */
    void on_stopButton_clicked();

    /**
    * @brief Adds "busy" running characters to status bar during computations.
    * @see guiUpdater
    */
    void statusUpdate();

    /**
    * @brief Adds new founded password to GUI.
    * @see guiUpdater
    */
    void infodeskUpdate(const QString& new_password);

signals:

    /**
    * @brief Signal for the guiupdater instance to finish.
    * Emitted when ~MainWindow() calls.
    * @see guiUpdater, ~MainWindow()
    */
    void signal_stopGuiUpdater();

private:
    Ui::MainWindow *ui;

    /**
    * @brief Stops the attack's computations and restores the initial state of GUI
    */
    void stopActions();

    /**
    * @brief Waits of the thread to exit, terminate if hangs, free associated resourses.
    * @param del_thread - pointer to the thread to remove
    */
    void destroyThread(QThread* del_thread);

    // attack target
    user* m_selecteduserobj;
    QThread* m_user_thread;

    // attack results reader
    guiUpdater* m_updateobj;
    QThread* m_update_thread;

    /**
    * @brief GUI spinner increment guard.
    */
    QMutex m_status_mutex;

    /**
    * @brief Users' db. Populates from the selected shadow file.
    */
    QVector<user> m_shadowUsers;

    /**
    * @brief Users' list initial misfiring flag.
    */
    bool m_initialsetup_usersCBox = 1;

    /**
    * @brief Time from start of the attack till it's interruption.
    */
    QElapsedTimer m_computation_timer;
};

#endif // MAINWINDOW_H
