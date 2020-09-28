#include "user.h"


std::map<QString, QString> user::m_halgorithm_types = {
    {"1", "MD5"},
    {"2a", "Blowfish"},
    //{"2y", "Eksblowfish"},
    {"5", "SHA-256"},
    {"6", "SHA-512"}
};


user::user(const QString& username, const QString& algid, const QString& salt, const QString& hashofpass, QObject *parent) : QObject(parent)
{
    Q_UNUSED(parent);
    setUser(username, algid, salt, hashofpass);
}


user::user(const user& other) : QObject(Q_NULLPTR)
{
    setUser(other.getUsername(), other.getUseralgid(), other.getUsersalt(), other.getUserhash());
}


user user::operator= (const user& other)
{
    user target;
    target.setUser(other.getUsername(), other.getUseralgid(), other.getUsersalt(), other.getUserhash());

    return target;
}


void user::setUser(const QString& username, const QString& algid, const QString& salt, const QString& hashofpass)
{
     this->m_username = username;
     this->m_algid = algid;
     this->m_salt = salt;
     this->m_hashofpass = hashofpass;
}


void user::collision_attack()
{
    // based on CPUs
    int threads_max = QThreadPool::globalInstance()->maxThreadCount();

    // init
    collisionAttackTask_CPU::setNewTarget(this);

    // username attack
    QThreadPool::globalInstance()->start(new collisionAttackTask_CPU(collisionAttackTask_CPU::Heuristics::full));

    // limited attack
    for (unsigned char pass_length = 1; pass_length <= collisionAttackTask_CPU::getOptimalMaxPL(); pass_length++)
    {
        if (collisionAttackTask_CPU::attackStatus() == false)
            break;

        QThreadPool::globalInstance()->start(new collisionAttackTask_CPU(collisionAttackTask_CPU::Heuristics::partial, pass_length));
    }

    // full eternal attack
    int password_length = 1;
    while (true)
    {
        if (collisionAttackTask_CPU::attackStatus() == false)
        {
            break;
        }
        else if (QThreadPool::globalInstance()->activeThreadCount() < threads_max)
        {
            QThreadPool::globalInstance()->start(new collisionAttackTask_CPU(collisionAttackTask_CPU::Heuristics::full, password_length));
            password_length++;
        }
        else
            QThread::sleep(2);
    }

    // till interruption
    QThreadPool::globalInstance()->waitForDone();
    emit signal_attackFinished();

    return;
}


QString user::getAlgorithmName(const QString& algid)
{
    if (! m_halgorithm_types.count(algid))
        return QString("");
    return m_halgorithm_types.at(algid);
}


void user::attack_interrupt()
{
    collisionAttackTask_CPU::stopAttack();
}
