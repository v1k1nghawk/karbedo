
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


user::user(const QJsonObject& json, QObject *parent) : QObject(Q_NULLPTR)
{
    Q_UNUSED(parent);

    if (json.contains("User") && json["User"].isString())
        m_username = json["User"].toString();
    else
        throw ParsingException{"\"User\" field not found in saved data"};

    if (json.contains("AlgId") && json["AlgId"].isString())
        m_algid = json["AlgId"].toString();
    else
        throw ParsingException{"\"AlgId\" field not found in saved data"};

    if (json.contains("Salt") && json["Salt"].isString())
        m_salt = json["Salt"].toString();
    else
        throw ParsingException{"\"Salt\" field not found in saved data"};

    if (json.contains("Hash") && json["Hash"].isString())
        m_hashofpass = json["Hash"].toString();
    else
        throw ParsingException{"\"Hash\" field not found in saved data"};
}


user::user(const user& other) : QObject(Q_NULLPTR)
{
    setUser(other.getName(), other.getAlgid(), other.getSalt(), other.getHash());
}


user user::operator= (const user& other)
{
    user target;
    target.setUser(other.getName(), other.getAlgid(), other.getSalt(), other.getHash());

    return target;
}


void user::setUser(const QString& username, const QString& algid, const QString& salt, const QString& hashofpass)
{
     this->m_username = username;
     this->m_algid = algid;
     this->m_salt = salt;
     this->m_hashofpass = hashofpass;
}


void user::write_to_json(QJsonObject& json) const
{
    json["User"] = m_username;
    json["AlgId"] = m_algid;
    json["Salt"] = m_salt;
    json["Hash"] = m_hashofpass;
}


void user::collision_attack()
{
    // init
    collisionAttackTask_CPU::setNewTarget(this);

    // username + dictionary attack
    QThreadPool::globalInstance()->start(new collisionAttackTask_CPU(collisionAttackTask_CPU::Heuristic::full));

    // restricted attack
    limited_attack(1);

    // unrestricted eternal attack
    unlimited_attack(1);

    // wait until interruption
    QThreadPool::globalInstance()->waitForDone();
    emit signal_attackFinished();

    return;
}


void user::resumed_collision_attack()
{
    // init
    collisionAttackTask_CPU::setNewTarget(this);

    /////////////////////////////////
    // determine cache threshold (upper bound), start each cached ("below threshold") task with its respective gained savepoint
    /////////////////////////////////

    // maximum reached milestone
    collisionAttackTask_CPU::Heuristic upperbound_heur = collisionAttackTask_CPU::Heuristic::full;
    uint upperbound_password_length = 1;

    while (true)
    {
        if (collisionAttackTask_CPU::attackStatus() != 1)
            break;

        QPair<QString, collisionAttackTask_CPU::Heuristic> task_init = collisionAttackTask_CPU::getCacheInit();
        if (task_init.first == QString(""))
            break;

        switch(task_init.second)
        {
            case collisionAttackTask_CPU::Heuristic::none:
                upperbound_heur = collisionAttackTask_CPU::Heuristic::none;
                if (upperbound_password_length < (uint)task_init.first.length())
                    upperbound_password_length = (uint)task_init.first.length();
                break;
            case collisionAttackTask_CPU::Heuristic::partial:
                if (upperbound_heur != collisionAttackTask_CPU::Heuristic::none)
                {
                    upperbound_heur = collisionAttackTask_CPU::Heuristic::partial;
                    if (upperbound_password_length < (uint)task_init.first.length())
                        upperbound_password_length = (uint)task_init.first.length();
                }
                break;
            case collisionAttackTask_CPU::Heuristic::full:
                break;
            default:
                continue;
                break;
        }

        QThreadPool::globalInstance()->start(new collisionAttackTask_CPU(task_init.second, task_init.first.length(), task_init.first));
    }
    // some cached attack found => go beyond
    if (upperbound_password_length != 1)
        upperbound_password_length++;


    /////////////////////////////////
    // start "above threshold" tasks
    /////////////////////////////////

    // restricted attack
    if ((upperbound_heur == collisionAttackTask_CPU::Heuristic::full || upperbound_heur == collisionAttackTask_CPU::Heuristic::partial))
    {
        limited_attack(upperbound_password_length);

        upperbound_password_length = 1;
    }

    // unrestricted eternal attack
    unlimited_attack(upperbound_password_length);

    // wait until interruption
    QThreadPool::globalInstance()->waitForDone();
    emit signal_attackFinished();

    return;
}


void user::limited_attack(const uint& initial_password_length)
{
    if (initial_password_length <= collisionAttackTask_CPU::getOptimalMaxPL())
    {
        for (unsigned char pass_length = initial_password_length; pass_length <= collisionAttackTask_CPU::getOptimalMaxPL(); pass_length++)
        {
            if (collisionAttackTask_CPU::attackStatus() != 1)
                break;

            QThreadPool::globalInstance()->start(new collisionAttackTask_CPU(collisionAttackTask_CPU::Heuristic::partial, pass_length));
        }
    }
}


void user::unlimited_attack(const uint& initial_password_length)
{
    uint current_password_length = initial_password_length;

    while (true)
    {
        if (collisionAttackTask_CPU::attackStatus() != 1)
            break;
        else if (QThreadPool::globalInstance()->activeThreadCount() < QThreadPool::globalInstance()->maxThreadCount()) // based on CPUs quant
        {
            QThreadPool::globalInstance()->start(new collisionAttackTask_CPU(collisionAttackTask_CPU::Heuristic::none, current_password_length));
            current_password_length++;
        }
        else
            QThread::sleep(2);
    }
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


void user::attack_save()
{
    collisionAttackTask_CPU::saveAttack();
}

