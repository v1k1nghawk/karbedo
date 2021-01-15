#ifndef GUIUPDATER_H
#define GUIUPDATER_H

#include <QApplication>

#include "collisionAttackTask_CPU.h"


class guiUpdater : public QObject
{
    Q_OBJECT

public:
    guiUpdater(QObject *parent = Q_NULLPTR);

    /**
    * @brief Implemented for connection registeration.
    */
    guiUpdater(const guiUpdater& other);

    /**
    * @brief Implemented for connection registeration.
    */
    ~guiUpdater() {}

    /**
    * @brief Checks the need for the guiUpdate instance.
    * @see startUpdate(), stopUpdate()
    */
    bool updateStatus(){return (bool)m_update_is_on.loadAcquire();}

public slots:

    /**
    * @brief Polls collisionAttackTask_CPU passwords' results and
    * updates the interface (spinner + new mined password).
    *
    * @see collisionAttackTask_CPU, signal_computing(), signal_pwfound()
    */
    void run_update();

    /**
    * @brief the guiUpdater is no longer needed.
    * run_update() completion command.
    *
    * @see MainWindow, run_update()
    */
    void stopUpdate(){m_update_is_on.store(0);}

signals:

    /**
    * @brief Notifies that user's computations is still active. Emitted during attack on the user's hash.
    * @see collisionAttackTask_CPU::attackStatus()
    */
    void signal_computing();

    /**
    * @brief New matching password has been found during the attack. Emitted when
    * collisionAttackTask_CPU::getHit() returns non-empty password.
    * @param pw - new found password
    *
    * @see collisionAttackTask_CPU::getHit()
    */
    void signal_pwfound(const QString& pw);

    /**
    * @brief The graphical interface should be updated. Emitted once in 1 seconds
    * when attack is on, and once in 2 seconds when idle.
    */
    void signal_repaint();

    /**
    * @brief guiUpdater has been quited.
    * @see stopUpdate()
    */
    void signal_updateFinished();

private:

    /**
    * @brief guiUpdater is needed. Actvates in the guiUpdater constructor.
    * @see MainWindow
    */
    void startUpdate(){m_update_is_on.store(1);}

    /**
    * @brief Checks the need for the updater object and refreshes GUI.
    * @return
    * @value FALSE - gets stop request and exits.
    * @value TRUE - GUI refreshed.
    * @see MainWindow, stopUpdate()
    */
    bool keepAlive();

    /**
    * @brief Flag of the updater nedeness.
    */
    QAtomicInt m_update_is_on;
};

Q_DECLARE_METATYPE(guiUpdater)

#endif // GUIUPDATER_H
