#include "guiupdater.h"


guiUpdater::guiUpdater(QObject *parent) : QObject(parent)
{
    Q_UNUSED(parent);
    startUpdate();
}


guiUpdater::guiUpdater(const guiUpdater& other) : QObject(Q_NULLPTR)
{
    this->m_update_is_on = other.m_update_is_on;
}


void guiUpdater::run_update()
{
    QThread::currentThread()->setPriority(QThread::LowPriority);

    QString password_to_gui;

    while (true)
    {
        if (keepAlive() == false)
        {
            emit signal_updateFinished();
            return;
        }

        // wait for start attacks
        if (collisionAttackTask_CPU::attackStatus() != true)
        {
            QThread::sleep(2);
        }
        else // attack has been started
        {
            // retrieve found passwords from the attack's buffer
            while (true)
            {
                if (keepAlive() == false)
                {
                    emit signal_updateFinished();
                    return;
                }

                // update GUI "busy" spinning
                emit signal_computing();

                password_to_gui = collisionAttackTask_CPU::getHit();
                if (password_to_gui == QString(""))
                {
                    // attack stopped
                    if (collisionAttackTask_CPU::attackStatus() == false)
                        break;

                    QThread::sleep(1);

                } else
                {
                    // update the GUI with a new find
                    emit signal_pwfound(password_to_gui);
                }
            }
        }
    }
}


bool guiUpdater::keepAlive()
{
    // check stop request
    if (updateStatus() == false)
        return false;

    // keep GUI more responsive during heavyload computations
    emit signal_repaint();
    qApp->processEvents();

    return true;
}
