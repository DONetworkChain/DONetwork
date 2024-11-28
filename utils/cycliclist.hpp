/**
 * *****************************************************************************
 * @file        cycliclist.hpp
 * @brief       
 * @date        2023-09-28
 * @copyright   don
 * *****************************************************************************
 */

#ifndef _CYCLICLIST_HPP_
#define _CYCLICLIST_HPP_

#include <utility>
#include <memory>
#include <functional>
#include <vector>




/**
 * @brief       
 * 
 */
template <typename T>
class ListIter
{

public:
	using value_type = T;
	using reference = T&;
	using const_referenct = const T&;
	using pointer = T*;
	using const_pointor = const T*;
	using size_type = size_t;
	using difference_type = ptrdiff_t;

	ListIter(pointer p = nullptr) : Iter(p) {}
	/**
	 * @brief
	 * 
	 * @param       rhs:
	 * @return      true
	 * @return      false
	*/
	bool operator==(const ListIter& rhs) const noexcept
	{
		return Iter == rhs.Iter;
	}
	/**
	 * @brief
	 * 
	 * @param       rhs:
	 * @return      true
	 * @return      false
	*/
	bool operator!=(const ListIter& rhs) const noexcept
	{
		return Iter != rhs.Iter;
	}
	/**
	 * @brief
	 * 
	 * @return      ListIter
	*/
	ListIter& operator++(int)
	{
        if(Iter==nullptr){
            return *this;
        }
		Iter = Iter->next();
		return *this;
	}
	/**
	 * @brief
	 * 
	 * @return      ListIter
	*/
	ListIter& operator--(int) {
        if(Iter==nullptr){
            return *this;
        }
		Iter = Iter->prev();
		return *this;
	}
	/**
	 * @brief
	 * 
	 * @param		value
	 * @return      ListIter
	*/
	ListIter operator+(int value) {

		pointer newPointer = Iter;
        if(Iter==nullptr){
            return ListIter<T>(nullptr);
        }
		if (value > 0) {
			for (int i = 0; i < value; i++) {
				newPointer = newPointer->next();
				
			}
			
		}
		else if(value <0) {
			for (int i = 0; i > value; i--) {
				newPointer = newPointer->prev();
				
			}
		}
		return ListIter<T>(newPointer);
	}
	/**
	 * @brief
	 * 
	 * @param		value
	 * @return      ListIter
	*/
	ListIter operator-(int value) {
		pointer newPointer = Iter;
        if(Iter==nullptr){
            return ListIter<T>(nullptr);
        }

		if (value > 0) {
			for (int i = 0; i < value; i++) {
				newPointer = newPointer->prev();
				
			}

		}
		else if (value < 0) {
			for (int i = 0; i > value; i--) {
				newPointer = newPointer->next();
				
			}
		}
		return ListIter<T>(newPointer);
	}
	/**
	 * @brief
	 * 
	 * @return      T&
	*/
	reference operator*()
	{
		return *Iter;
	}
	/**
	 * @brief
	 * 
	 * @return      T*
	*/
	pointer getPtr() {
		return Iter;
	}
	/**
	 * @brief
	 * 
	 * @return      T*
	*/
	pointer operator->()
	{
		return Iter;
	}
private:
	pointer Iter=nullptr;
};


template <typename T>
class Cycliclist {
public:
	template<typename T_>
	class Node {
	public:
		Node(const T_& value) { data = value; }
		T_ data;
		Node<T_>* next() { return next_; }
		Node<T_>* prev() { return pre; }
	private:
		friend class Cycliclist<T_>;



		Node<T_>* pre = nullptr;
		Node<T_>* next_ = nullptr;
	};
	using iterator = ListIter<Node<T>>;
	Cycliclist() {}

	~Cycliclist(){
		clear();
	}

	Cycliclist(Cycliclist& list) {
		
	}

	Cycliclist(Cycliclist&& list) {
		m_size = list.m_size;
		head = list.head;
		last = list.last;
	}
	/**
	 * @brief
	 * 
	 * @param		iter:
	 * @return      ListIter<Node<T>>
	*/
	iterator next(iterator iter) {
		return iter->next();
	}
	/**
	 * @brief
	 * 
	 * @return      ListIter<Node<T>>
	*/
	iterator begin() {
		return iterator(head);
	}
	/**
	 * @brief
	 * 
	 * @return      ListIter<Node<T>>
	*/
	iterator end() {
		return iterator(last);
	}
	/**
	 * @brief
	 * 
	 * @return      int
	*/
	int size() {
		return m_size;
	}
	/**
	 * @brief
	 * 
	 * @return      true
	 * @return      false
	*/
	bool isEmpty() {
		if (m_size == 0) {
			return true;
		}
		return false;
	}
	/**
	 * @brief
	 * 
	 * @param      value
	*/
	void push_front(const T& value) {
		if (head == nullptr) {

			Node<T>* node = new Node<T>(value);
			head = node;
			node->next_ = node;
			last = node;
			node->pre = node;
		}
		else {
			Node<T>* temp_head = nullptr;
			Node<T>* node = new Node<T>(value);
			temp_head = head;
			head = node;
			node->next_ = temp_head;
			node->pre = temp_head->pre;
			temp_head->pre = node;
			last->next_ = node;
		}
		m_size++;
	}
	/**
	 * @brief
	 * 
	 * @param      value
	*/
	void push_back(const T& value) {
		if (head == nullptr) {

			Node<T>* node = new Node<T>(value);
			head = node;
			last = node;
			node->pre = node;
			node->next_ = node;
		}
		else {
			Node<T>* temp_last = nullptr;
			Node<T>* node = new Node<T>(value);
			temp_last = last;
			node->next_ = temp_last->next_;
			node->pre = temp_last;
			temp_last->next_ = node;
			last = node;
			head->pre = node;

		}
		m_size++;
	}
	/**
	 * @brief
	 * 
	 * @param       index:
	 * @return		T&
	*/
	T& operator[](int index) {
		auto ite = begin();
		ite =ite+index;
		return ite->data;
	}
	/**
	 * @brief
	 * 
	 * @param       lamda:
	 * @return		std::vector<iterator>
	*/
	std::vector<iterator> filter(std::function<bool(iterator)> lamda) {
		auto ite = this->begin();
		std::vector<iterator> res;
		for (; ite != this->end(); ite++) {
			if (lamda(ite)) {
				res.push_back(ite);
			}
		}
		if(lamda(ite)){
			res.push_back(ite);
		}
		return res;
	}
	/**
	 * @brief
	 * 
	 * @param       lamda:
	 * @return		iterator
	*/
	iterator remove(iterator iter) {

		if (head == nullptr) {
			return iterator(nullptr);
		}

		Node<T>* tempNode = iter.getPtr();
		Node<T>* next_node = tempNode->next_;

		if (iter.getPtr() == head) {
			head = next_node;
		}
		if (iter.getPtr() == last) {
			last = tempNode->pre;
		}

		tempNode->pre->next_ = tempNode->next_;
		tempNode->next_->pre = tempNode->pre;
		delete tempNode;
		m_size--;
		if (m_size == 0) {
			return iterator(nullptr);
		}
		return iterator(next_node);
	}
	/**
	 * @brief
	 * 
	 * @param       lamda:
	 * @return		iterator
	*/
	iterator remove(std::function<bool(iterator)> lamda) {

		auto ite = this->begin();
		for (; ite != this->end(); ite++) {
			if (lamda(ite)) {
				Node<T>* next_node = ite->next();
				remove(ite);
				return iterator(next_node);
				break;
			}
		}
		if(lamda(ite)){
			Node<T>* next_node = ite->next();
				remove(ite);
				return iterator(next_node);
		}

		return iterator(nullptr);
	}

	/**
	 * @brief
	*/
	void clear() {
		if(head == nullptr)
		{
			return;
		}
		Node<T>* nextNode = head->next();
		head->next_ = nullptr;
		while (nextNode != nullptr) {
			Node<T>* DeleteNode = nextNode;
			nextNode = nextNode->next();
			delete DeleteNode;
		}
	}
private:
	Node<T>* head = nullptr;
	Node<T>* last = nullptr;
	int m_size = 0;
};


#endif
