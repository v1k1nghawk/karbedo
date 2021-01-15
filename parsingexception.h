#ifndef PARSINGEXCEPTION_H
#define PARSINGEXCEPTION_H

#include <QException>


/**
 * @class ParsingException
 * @brief Raise in case of incompatible storage file format.
 */
class ParsingException : public QException
{
public:
    ParsingException(const QString& err_text=" ") noexcept : err_msg(err_text) {}
    ParsingException(const ParsingException& re) {this->err_msg = re.err_msg; }
    ~ParsingException() override {}

    void raise() const override { throw *this; }
    ParsingException *clone() const override { return new ParsingException(*this); }
    const char *what() const noexcept override { return this->err_msg.toStdString().c_str(); }

private:
    QString err_msg;
};







#endif // PARSINGEXCEPTION_H
