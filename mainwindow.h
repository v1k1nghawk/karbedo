#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidgetItem>
#include <QFileDialog>
#include <QDate>
#include <QStringListModel>
#include <QElapsedTimer>
#include <boost/container/vector.hpp>
#include <general.h>
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
    * @brief Choose target user from a selected file and run the attack.
    * @see user, startActions()
    */
    void on_usersCBox_currentTextChanged();

    /**
    * @brief "STOP" handler, stopActions() caller.
    * @see stopActions()
    */
    void on_stopButton_clicked();

    /**
    * @brief "RESUME" handler, resumeActions() caller.
    * @see resumeActions()
    */
    void on_resumeButton_clicked();

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

    void closeEvent(QCloseEvent *event);

    /**
    * @brief
    * @param mode - type of the application behaviour w.r.t. user's selection.
    * @value 0 - Runs brand new attack.
    * @value 1 - Continues the suspended attack's computations after app's restart.
    */
    void startAttackActions(const bool mode);

    /**
    * @brief Stops the attack's computations and restores the initial state of GUI.
    */
    void stopAttackActions();

    /**
    * @brief Saves and aborts the attack's computations.
    */
    void abortAttackActions();

    /**
    * @brief Checks if the cache file exists.
    * @return
    * @value false - file does not exist.
    * @value true  - file exists.
    * @see load_cache()
    */
    bool isCacheExists();

    /**
    * @brief Gets data of the last aborted attack from the cache.
    * @param json - storage for loaded data
    * @return
    * @value false - errors during data loading.
    * @value true  - data successfully loaded.
    * @see save_cache(), clear_cache()
    */
    bool load_cache(QJsonObject& json);

    /**
    * @brief Stores data of the aborted attack to the cache.
    * @param current_attack_data - aborted attack's data.
    * @return
    * @value false - errors during data saving.
    * @value true  - data successfully saved.
    * @see load_cache(), clear_cache()
    */
    bool save_cache(QJsonDocument current_attack_data);

    /**
    * @brief Deletes data of the aborted attack from the cache.
    * @return
    * @value false - errors during clearing the cache.
    * @value true  - cache successfully cleared.
    * @see load_cache(), save_cache()
    */
    bool clear_cache();

    /**
    * @brief Waits of the thread to exit, terminate if hangs, free associated resourses.
    * @param del_thread - pointer to the thread to remove
    */
    void destroyThread(QThread* del_thread);

    // attack target
    user* m_selecteduserobj = Q_NULLPTR;
    QThread* m_user_thread = Q_NULLPTR;

    // attack results reader
    guiUpdater* m_updateobj = Q_NULLPTR;
    QThread* m_update_thread = Q_NULLPTR;

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

    /**
    * @brief Path to the directory of temporarily saved application files.
    */
    QString m_cache_path;

    /**
    * @brief Path to the file with the last aborted attack's data.
    */
    QString m_cache_file;
};

#endif // MAINWINDOW_H
